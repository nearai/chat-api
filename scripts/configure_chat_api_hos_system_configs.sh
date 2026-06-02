#!/usr/bin/env bash
set -euo pipefail

# Configure chat-api system configs for House-of-Stake payments.
#
# Required:
#   ADMIN_SESSION_TOKEN=sess_... ./scripts/configure_chat_api_hos_system_configs.sh
#
# Optional:
#   CHAT_API_URL=http://localhost:8080
#   DRY_RUN=1
#
# Optional Stripe preservation/addition:
#   STRIPE_STARTER_PRICE_ID=price_...
#   STRIPE_BASIC_PRICE_ID=price_...
#   STRIPE_PRO_PRICE_ID=price_...
#   STRIPE_CREDIT_PRICE_ID=price_...

CHAT_API_URL="${CHAT_API_URL:-http://localhost:8080}"
ADMIN_SESSION_TOKEN="${ADMIN_SESSION_TOKEN:-}"

HOS_AGENT_STARTER_PRICE_ID="${HOS_AGENT_STARTER_PRICE_ID:-price_RjiajH4KEZ43w68DgY5xVaVU}"
HOS_AGENT_BASIC_PRICE_ID="${HOS_AGENT_BASIC_PRICE_ID:-price_h577VYQUEynPA3uQt1u1neGn}"
HOS_AGENT_PRO_PRICE_ID="${HOS_AGENT_PRO_PRICE_ID:-price_7EAls0E844ULR06EEl53fQoI}"
HOS_CREDIT_PRICE_ID="${HOS_CREDIT_PRICE_ID:-price_z2EbTifr7Nyqwt6v5kFqSiUb}"

DEFAULT_CREDITS_PROVIDER="${DEFAULT_CREDITS_PROVIDER:-stripe}"
DRY_RUN="${DRY_RUN:-0}"

if [[ -z "$ADMIN_SESSION_TOKEN" ]]; then
  echo "ADMIN_SESSION_TOKEN is required" >&2
  exit 1
fi

export HOS_AGENT_STARTER_PRICE_ID
export HOS_AGENT_BASIC_PRICE_ID
export HOS_AGENT_PRO_PRICE_ID
export HOS_CREDIT_PRICE_ID
export DEFAULT_CREDITS_PROVIDER

python3 - "$CHAT_API_URL" "$ADMIN_SESSION_TOKEN" "$DRY_RUN" <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request

chat_api_url = sys.argv[1].rstrip("/")
admin_session_token = sys.argv[2]
dry_run = sys.argv[3] == "1"


def request_json(method, path, body=None):
    data = None
    headers = {
        "Authorization": f"Bearer {admin_session_token}",
        "Accept": "application/json",
    }
    if body is not None:
        data = json.dumps(body, sort_keys=True).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        f"{chat_api_url}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")
        raise SystemExit(
            f"{method} {path} failed with HTTP {error.code}: {details}"
        ) from error


def env(name, default=None):
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) else value


current = request_json("GET", "/v1/admin/configs") or {}
subscription_plans = current.get("subscription_plans") or {}

hos_plans = {
    "starter": {
        "price_id": env("HOS_AGENT_STARTER_PRICE_ID"),
        "agent_instances": {"max": 1},
    },
    "basic": {
        "price_id": env("HOS_AGENT_BASIC_PRICE_ID"),
        "agent_instances": {"max": 2},
    },
    "pro": {
        "price_id": env("HOS_AGENT_PRO_PRICE_ID"),
        "agent_instances": {"max": 5},
    },
}

stripe_plan_env = {
    "starter": env("STRIPE_STARTER_PRICE_ID", ""),
    "basic": env("STRIPE_BASIC_PRICE_ID", ""),
    "pro": env("STRIPE_PRO_PRICE_ID", ""),
}

for plan_name, hos_config in hos_plans.items():
    plan = dict(subscription_plans.get(plan_name) or {})
    providers = dict(plan.get("providers") or {})
    providers["house-of-stake"] = {"price_id": hos_config["price_id"]}
    stripe_price_id = stripe_plan_env.get(plan_name)
    if stripe_price_id:
        providers["stripe"] = {"price_id": stripe_price_id}
    plan["providers"] = providers
    plan["agent_instances"] = hos_config["agent_instances"]
    subscription_plans[plan_name] = plan

credits = dict(current.get("credits") or {})
credit_providers = dict(credits.get("providers") or {})
credit_providers["house-of-stake"] = {"price_id": env("HOS_CREDIT_PRICE_ID")}
stripe_credit_price_id = env("STRIPE_CREDIT_PRICE_ID", "")
if stripe_credit_price_id:
    credit_providers["stripe"] = {"price_id": stripe_credit_price_id}
credits["providers"] = credit_providers
credits["default_provider"] = env("DEFAULT_CREDITS_PROVIDER", "stripe")

payload = {
    "subscription_plans": subscription_plans,
    "credits": credits,
}

print(json.dumps(payload, indent=2, sort_keys=True))

if dry_run:
    print("DRY_RUN=1; not PATCHing /v1/admin/configs")
    raise SystemExit(0)

updated = request_json("PATCH", "/v1/admin/configs", payload)
print("Updated /v1/admin/configs")
print(json.dumps(updated, indent=2, sort_keys=True))
PY
