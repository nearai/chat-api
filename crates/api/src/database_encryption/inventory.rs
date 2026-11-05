use super::*;
#[derive(Default)]
pub(super) struct Inventory {
    pub(super) legacy_confidential: Vec<Value>,
    pub(super) unclassified: Vec<Value>,
}

pub(super) fn classification(
    table: &str,
    column: &str,
    data_type: &str,
) -> Option<(&'static str, &'static str)> {
    if FIELDS
        .iter()
        .any(|field| field.table == table && field.column == column)
    {
        return Some(("encrypt", "Stage I confidential field"));
    }
    if let Some((_, _, reason)) = APPROVED
        .iter()
        .find(|(known_table, known_column, _)| *known_table == table && *known_column == column)
    {
        return Some(("approved_plaintext", reason));
    }
    if table == "response_authors" || (table == "conversations" && column == "title") {
        return Some((
            "legacy_confidential",
            "Legacy conversation data must be removed or encrypted before migration",
        ));
    }
    if REVIEWED_PLAINTEXT_FIELDS
        .iter()
        .any(|(known_table, known_column, _)| *known_table == table && *known_column == column)
    {
        return Some((
            "approved_plaintext",
            "Reviewed and approved for plaintext storage outside the TEE",
        ));
    }
    if APPROVED_TEXT_FIELDS
        .iter()
        .any(|(known_table, known_column)| *known_table == table && *known_column == column)
    {
        return Some((
            "approved_plaintext",
            "Reviewed enum, identifier, hash, or numeric text",
        ));
    }
    (CLASSIFIED_TABLES.contains(&table) && STRUCTURAL_TYPES.contains(&data_type)).then_some((
        "approved_plaintext",
        "Reviewed structural or operational value",
    ))
}

pub(super) async fn inventory(state: &AppState) -> anyhow::Result<Inventory> {
    let client = state.db_pool.get().await?;
    inventory_with_client(&client).await
}

pub(super) async fn inventory_with_client(
    client: &impl deadpool_postgres::GenericClient,
) -> anyhow::Result<Inventory> {
    let rows = client.query("SELECT columns.table_name,columns.column_name,columns.data_type FROM information_schema.columns columns JOIN information_schema.tables tables USING(table_schema,table_name) WHERE columns.table_schema='public' AND tables.table_type='BASE TABLE' AND columns.table_name <> 'refinery_schema_history' ORDER BY columns.table_name,columns.ordinal_position", &[]).await?;
    let mut inventory = Inventory::default();
    for row in rows {
        let table: String = row.get(0);
        let column: String = row.get(1);
        let data_type: String = row.get(2);
        let (kind, reason) = classification(&table, &column, &data_type).unwrap_or((
            "unclassified",
            "No explicit sensitive or plaintext classification",
        ));
        let entry = json!({"table":table,"column":column,"data_type":data_type,"classification":kind,"reason":reason});
        match kind {
            "legacy_confidential" => inventory.legacy_confidential.push(entry),
            "unclassified" => inventory.unclassified.push(entry),
            _ => {}
        }
    }
    Ok(inventory)
}
