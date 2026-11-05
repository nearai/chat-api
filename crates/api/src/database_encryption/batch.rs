use super::*;
use database::field_encryption::KeyRing;

pub(super) struct Batch<'a, 'tx> {
    pub(super) tx: &'a deadpool_postgres::Transaction<'tx>,
    pub(super) field: &'a Field,
    pub(super) config: &'a services::db_pool::FieldEncryptionConfig,
    pub(super) ring: &'a KeyRing,
    pub(super) mode: &'a str,
    pub(super) action: &'a str,
}

impl Batch<'_, '_> {
    pub(super) async fn process(
        &self,
        row: &deadpool_postgres::tokio_postgres::Row,
        progress: &mut Progress,
    ) -> anyhow::Result<()> {
        let id: Uuid = row.get(0);
        progress.record(self.field, |c| c.processed += 1);
        let raw: Option<String> = row.get(1);
        let Some(raw) = raw else { return Ok(()) };
        if let Some(key_id) = stored_key_id(&raw) {
            progress.record(self.field, |c| {
                *c.by_key_id.entry(key_id.clone()).or_default() += 1
            });
        }
        let classified = match read_value(self.ring, self.field, id, &raw) {
            Ok(value) => value,
            Err(error) => {
                if self.action == "encrypt"
                    && self.mode == "execute"
                    && matches!(self.field.kind, Kind::AgentSecret)
                {
                    return Err(error);
                }
                progress.invalid(self.field, id);
                return Ok(());
            }
        };
        let stored_token: Option<Vec<u8>> = row.get(2);
        let (plaintext, stale, token_only) = match classified {
            StoredValue::Current(plaintext) => {
                progress.record(self.field, |c| c.already_current += 1);
                let matches = search_token_matches(
                    &self.config.key,
                    self.field,
                    &plaintext,
                    stored_token.as_deref(),
                );
                if self.action != "rewrap" {
                    if !matches {
                        progress.invalid(self.field, id);
                    }
                    return Ok(());
                }
                if matches {
                    return Ok(());
                }
                (plaintext, false, true)
            }
            StoredValue::Stale(plaintext) => {
                progress.record(self.field, |c| c.stale += 1);
                if self.action != "rewrap" {
                    if !search_token_matches(
                        &self.config.key,
                        self.field,
                        &plaintext,
                        stored_token.as_deref(),
                    ) {
                        progress.invalid(self.field, id);
                    }
                    return Ok(());
                }
                (plaintext, true, false)
            }
            StoredValue::LegacyEncrypted(plaintext) => {
                if self.mode != "execute" || self.action == "rewrap" {
                    progress.record(self.field, |c| c.legacy_encrypted += 1);
                }
                if self.action == "rewrap" || self.mode != "execute" {
                    return Ok(());
                }
                (plaintext, false, false)
            }
            StoredValue::Plaintext(plaintext) => {
                if self.mode != "execute" || self.action == "rewrap" {
                    progress.record(self.field, |c| c.plaintext += 1);
                }
                if self.action == "rewrap" || self.mode != "execute" {
                    return Ok(());
                }
                (plaintext, false, false)
            }
        };
        let token = self
            .field
            .token
            .map(|(_, domain)| {
                database::field_encryption::search_token(
                    &self.config.key,
                    domain,
                    &normalized_token_value(domain, &plaintext),
                )
            })
            .transpose()?;
        let changed_token = token.as_deref() != stored_token.as_deref();
        let value = if token_only || self.mode == "dry_run" {
            raw
        } else {
            database::field_encryption::encrypt(
                &self.config.key,
                &self.config.key_id,
                self.field.table,
                self.field.column,
                id,
                &plaintext,
            )?
        };
        let rewrite = super::writes::RowRewrite { id, value, token };
        if self.mode == "dry_run" {
            if !projection::try_rewrite(self, &rewrite).await? {
                progress.conflict(self.field, id);
                return Ok(());
            }
        } else if !super::writes::write_row(self, &rewrite).await? {
            progress.conflict(self.field, id);
            return Ok(());
        }
        progress.record(self.field, |c| {
            if stale {
                c.rewrapped += 1;
            }
            if self.action == "encrypt" {
                c.encrypted += 1;
            }
            if self.action == "rewrap" && changed_token {
                c.tokens_rewritten += 1;
            }
        });
        Ok(())
    }
}
