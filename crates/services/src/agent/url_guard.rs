//! Validation and network guards for outbound requests to agent instances.
//!
//! Agent instance URLs are stored data rather than operator configuration, so every
//! request built from them goes through the checks in this module:
//!
//! * [`validate_agent_url`] parses and checks a URL before it is stored or used.
//! * [`join_url_path`] appends a request path to a validated base URL.
//! * [`guarded_client_builder`] returns an HTTP client builder whose DNS resolver and
//!   redirect policy apply the same destination rules at connection time.
//!
//! Private network ranges stay allowed because agent infrastructure may be reached
//! over private networks. The blocked set is limited to destinations that are never
//! valid agent endpoints.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, bail};
use url::{Host, Url};

/// Maximum number of redirects followed by a guarded client.
const MAX_REDIRECTS: usize = 10;

/// Returns `true` for addresses that must never be used as an agent endpoint.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_ipv4(v4),
        IpAddr::V6(v6) => is_forbidden_ipv6(v6),
    }
}

fn is_forbidden_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        // 0.0.0.0/8 ("this network")
        || a == 0
        // 10.0.2.0/24: hypervisor user-mode networking subnet
        || (a == 10 && b == 0 && c == 2)
}

fn is_forbidden_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_unicast_link_local() {
        return true;
    }

    // IPv4-mapped and IPv4-compatible addresses
    if let Some(v4) = ip.to_ipv4() {
        return is_forbidden_ipv4(v4);
    }

    // NAT64 well-known prefix 64:ff9b::/96
    let segments = ip.segments();
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [hi, lo] = [segments[6], segments[7]];
        let v4 = Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
        return is_forbidden_ipv4(v4);
    }

    false
}

fn is_forbidden_domain(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    domain == "localhost" || domain.ends_with(".localhost")
}

/// Checks the scheme, credentials and host of an already-parsed URL.
fn check_destination(url: &Url, field_name: &str) -> anyhow::Result<()> {
    if url.scheme() != "https" && url.scheme() != "http" {
        bail!("Invalid {field_name}: must use http or https scheme");
    }

    if !url.username().is_empty() || url.password().is_some() {
        bail!("Invalid {field_name}: embedded credentials are not allowed");
    }

    let forbidden = match url.host() {
        None => bail!("Invalid {field_name}: missing host"),
        Some(Host::Domain(domain)) => is_forbidden_domain(domain),
        Some(Host::Ipv4(ip)) => is_forbidden_ipv4(ip),
        Some(Host::Ipv6(ip)) => is_forbidden_ipv6(ip),
    };
    if forbidden {
        bail!("Invalid {field_name}: destination is not allowed");
    }

    Ok(())
}

/// Parses and validates a URL that points at agent infrastructure.
///
/// The URL must use `http` or `https`, have a host, carry no embedded credentials and
/// not point at a forbidden destination. Numeric host forms are normalized by the
/// URL parser before the check.
pub fn validate_agent_url(raw: &str, field_name: &str) -> anyhow::Result<Url> {
    let url = Url::parse(raw).map_err(|_| anyhow!("Invalid {field_name}: not a valid URL"))?;
    check_destination(&url, field_name)?;
    Ok(url)
}

/// Appends `path` (optionally with a query string) to the path of `base`.
///
/// The base URL's query string is kept, and the appended path always becomes part of
/// the URL path, never part of the query or fragment.
pub fn join_url_path(base: &Url, path: &str) -> anyhow::Result<Url> {
    if path.contains('#') {
        bail!("Invalid request path: fragments are not allowed");
    }
    let (path_part, query_part) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };

    let mut url = base.clone();
    url.set_fragment(None);

    let base_path = base.path().trim_end_matches('/');
    let suffix = path_part.trim_start_matches('/');
    url.set_path(&format!("{base_path}/{suffix}"));

    if let Some(extra) = query_part.filter(|q| !q.is_empty()) {
        let query = match base.query().filter(|q| !q.is_empty()) {
            Some(existing) => format!("{existing}&{extra}"),
            None => extra.to_string(),
        };
        url.set_query(Some(&query));
    }

    Ok(url)
}

/// Returns the configured manager URL matching `candidate`, ignoring trailing slashes.
///
/// Callers should use the returned configured value, not `candidate`, when building
/// requests to the manager.
pub fn match_configured_manager<'a>(configured: &'a [String], candidate: &str) -> Option<&'a str> {
    let candidate = candidate.trim_end_matches('/');
    configured
        .iter()
        .map(String::as_str)
        .find(|url| url.trim_end_matches('/') == candidate)
}

/// DNS resolver that drops forbidden addresses from every lookup result.
///
/// Applying the check at resolution time also covers host names that resolve to a
/// forbidden address and names whose records change between validation and use.
#[derive(Debug, Default, Clone, Copy)]
pub struct GuardedResolver;

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|addr| !is_forbidden_ip(addr.ip()))
                .collect();

            if addrs.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "resolved address is not allowed",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Redirect policy that validates every redirect target.
pub fn guarded_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        if check_destination(attempt.url(), "redirect target").is_err() {
            return attempt.error("redirect target is not allowed");
        }
        attempt.follow()
    })
}

/// Returns a client builder that applies the destination rules at connection time.
pub fn guarded_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(GuardedResolver))
        .redirect(guarded_redirect_policy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::dns::Resolve;

    #[test]
    fn forbidden_ipv4_addresses() {
        for ip in [
            "127.0.0.1",
            "127.1.2.3",
            "0.0.0.0",
            "0.1.2.3",
            "169.254.169.254",
            "10.0.2.2",
            "10.0.2.3",
            "255.255.255.255",
            "224.0.0.1",
        ] {
            assert!(
                is_forbidden_ip(ip.parse().unwrap()),
                "{ip} should be forbidden"
            );
        }
    }

    #[test]
    fn allowed_ipv4_addresses() {
        for ip in [
            "8.8.8.8",
            "10.0.1.2",
            "10.0.3.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
        ] {
            assert!(
                !is_forbidden_ip(ip.parse().unwrap()),
                "{ip} should be allowed"
            );
        }
    }

    #[test]
    fn forbidden_ipv6_addresses() {
        for ip in [
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.2.2",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:202",
        ] {
            assert!(
                is_forbidden_ip(ip.parse().unwrap()),
                "{ip} should be forbidden"
            );
        }
    }

    #[test]
    fn allowed_ipv6_addresses() {
        for ip in [
            "2001:db8::1",
            "2606:4700::1111",
            "fd00::1",
            "64:ff9b::808:808",
        ] {
            assert!(
                !is_forbidden_ip(ip.parse().unwrap()),
                "{ip} should be allowed"
            );
        }
    }

    #[test]
    fn validate_accepts_regular_urls() {
        for raw in [
            "https://agent.example.com",
            "https://agent.example.com/path",
            "http://agent.example.com:8080/path",
            "https://name.agents.example.com/?token=abc",
            "https://10.1.2.3:8443/api",
            "https://[2001:db8::1]/",
        ] {
            assert!(
                validate_agent_url(raw, "instance_url").is_ok(),
                "{raw} should be accepted"
            );
        }
    }

    #[test]
    fn validate_rejects_forbidden_destinations() {
        for raw in [
            "http://localhost:8000",
            "http://LOCALHOST./",
            "http://api.localhost/",
            "http://127.0.0.1:8443/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://127.1/",
            "http://0.0.0.0/",
            "http://10.0.2.2:44404/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[fe80::1]/",
        ] {
            let err = validate_agent_url(raw, "instance_url").unwrap_err();
            assert!(
                err.to_string().contains("destination is not allowed"),
                "{raw}: unexpected error {err}"
            );
        }
    }

    #[test]
    fn validate_rejects_bad_shapes() {
        assert!(validate_agent_url("", "f").is_err());
        assert!(validate_agent_url("/relative/path", "f").is_err());
        assert!(validate_agent_url("file:///etc/passwd", "f").is_err());
        assert!(validate_agent_url("javascript:alert(1)", "f")
            .unwrap_err()
            .to_string()
            .contains("must use http or https scheme"));
        assert!(validate_agent_url("https://user:pass@example.com/", "f")
            .unwrap_err()
            .to_string()
            .contains("embedded credentials"));
        assert!(validate_agent_url("https://user@example.com/", "f").is_err());
    }

    #[test]
    fn join_appends_to_path() {
        let base = Url::parse("https://agent.example.com").unwrap();
        assert_eq!(
            join_url_path(&base, "/v1/instances/abc/backups")
                .unwrap()
                .as_str(),
            "https://agent.example.com/v1/instances/abc/backups"
        );

        let base = Url::parse("https://agent.example.com/api/").unwrap();
        assert_eq!(
            join_url_path(&base, "/v1/models").unwrap().as_str(),
            "https://agent.example.com/api/v1/models"
        );
    }

    #[test]
    fn join_keeps_appended_path_out_of_the_query() {
        let base = Url::parse("https://agent.example.com/base?token=abc&x=").unwrap();
        let joined = join_url_path(&base, "/v1/instances/abc/backups").unwrap();
        assert_eq!(joined.path(), "/base/v1/instances/abc/backups");
        assert_eq!(joined.query(), Some("token=abc&x="));
    }

    #[test]
    fn join_merges_query_strings() {
        let base = Url::parse("https://agent.example.com/?token=abc").unwrap();
        let joined = join_url_path(&base, "/v1/items?limit=5").unwrap();
        assert_eq!(joined.path(), "/v1/items");
        assert_eq!(joined.query(), Some("token=abc&limit=5"));

        let base = Url::parse("https://agent.example.com/").unwrap();
        let joined = join_url_path(&base, "v1/items?limit=5").unwrap();
        assert_eq!(
            joined.as_str(),
            "https://agent.example.com/v1/items?limit=5"
        );
    }

    #[test]
    fn join_rejects_fragments_and_drops_base_fragment() {
        let base = Url::parse("https://agent.example.com/#frag").unwrap();
        assert!(join_url_path(&base, "/v1/a#b").is_err());
        assert_eq!(
            join_url_path(&base, "/v1/a").unwrap().as_str(),
            "https://agent.example.com/v1/a"
        );
    }

    #[test]
    fn join_keeps_percent_encoded_segments() {
        let base = Url::parse("https://agent.example.com").unwrap();
        let joined = join_url_path(&base, "/v1/instances/a%2Fb/backup").unwrap();
        assert_eq!(joined.path(), "/v1/instances/a%2Fb/backup");
    }

    #[test]
    fn match_configured_manager_requires_exact_url() {
        let configured = vec![
            "https://agents.example.com/api/crabshack".to_string(),
            "https://other.example.com/".to_string(),
        ];
        assert_eq!(
            match_configured_manager(&configured, "https://agents.example.com/api/crabshack/"),
            Some("https://agents.example.com/api/crabshack")
        );
        assert_eq!(
            match_configured_manager(&configured, "https://other.example.com"),
            Some("https://other.example.com/")
        );
        assert_eq!(
            match_configured_manager(&configured, "https://agents.example.com/api"),
            None
        );
        assert_eq!(
            match_configured_manager(&configured, "http://10.0.2.2:8443/"),
            None
        );
        assert_eq!(
            match_configured_manager(&[], "https://agents.example.com"),
            None
        );
    }

    #[tokio::test]
    async fn resolver_rejects_names_resolving_to_forbidden_addresses() {
        let name: reqwest::dns::Name = "localhost".parse().unwrap();
        assert!(GuardedResolver.resolve(name).await.is_err());
    }
}
