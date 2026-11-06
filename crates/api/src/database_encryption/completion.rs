use super::*;

pub(super) async fn finish(
    tx: &deadpool_postgres::Transaction<'_>,
    id: Uuid,
    mode: &str,
    fields: &[&Field],
    progress: &Progress,
) -> anyhow::Result<()> {
    let inventory = if mode == "verify" {
        inventory_with_client(tx).await?
    } else {
        Inventory::default()
    };
    let mut missing_encryption_contexts = 0i64;
    for field in fields {
        let row_id = row_id_expression(field, None);
        let query = format!(
            "SELECT count(*) FROM {table} WHERE {column} IS NOT NULL AND {row_id} IS NULL",
            table = field.table,
            column = field.column
        );
        missing_encryption_contexts += tx.query_one(&query, &[]).await?.get::<_, i64>(0);
    }
    let totals = &progress.totals;
    let pass = totals.invalid_envelopes == 0
        && totals.token_conflicts == 0
        && (mode != "verify"
            || totals.plaintext == 0
                && totals.legacy_encrypted == 0
                && totals.stale == 0
                && missing_encryption_contexts == 0
                && inventory.unclassified.is_empty()
                && inventory.legacy_confidential.is_empty());
    tx.execute("UPDATE database_encryption_jobs SET status=CASE WHEN cancel_requested_at IS NULL THEN 'completed' ELSE 'cancelled' END,completed_at=NOW(),progress=progress||$2 WHERE id=$1 AND status='running'", &[&id, &json!({"pass":pass,"missing_encryption_contexts":missing_encryption_contexts,"legacy_confidential":inventory.legacy_confidential,"unclassified":inventory.unclassified})]).await?;
    Ok(())
}
