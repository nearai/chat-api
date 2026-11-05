use super::*;
use deadpool_postgres::tokio_postgres::error::SqlState;

/// One atomic replacement of an encrypted value and its optional lookup token.
pub(super) struct RowRewrite {
    pub(super) id: Uuid,
    pub(super) value: String,
    pub(super) token: Option<Vec<u8>>,
}

/// Only token rewraps need row savepoints to isolate unique violations.
pub(super) async fn write_batch(
    batch: &batch::Batch<'_, '_>,
    rewrites: &[RowRewrite],
) -> anyhow::Result<u64> {
    if rewrites.is_empty() {
        return Ok(0);
    }
    let ids: Vec<_> = rewrites.iter().map(|row| row.id).collect();
    let values: Vec<_> = rewrites.iter().map(|row| row.value.as_str()).collect();
    let field = batch.field;
    let row_id = row_id_expression(field, Some("target"));
    let sql = if let Some((token_column, _)) = field.token {
        format!(
            "UPDATE {table} target SET {column}=batch.value,{token_column}=batch.token
             FROM UNNEST($1::uuid[],$2::text[],$3::bytea[]) AS batch(id,value,token)
             WHERE {row_id}=batch.id",
            table = field.table,
            column = field.column,
        )
    } else {
        format!(
            "UPDATE {table} target SET {column}=batch.value
             FROM UNNEST($1::uuid[],$2::text[]) AS batch(id,value)
             WHERE {row_id}=batch.id",
            table = field.table,
            column = field.column,
        )
    };
    let updated = if field.token.is_some() {
        let tokens: Vec<_> = rewrites.iter().map(|row| row.token.as_deref()).collect();
        batch.tx.execute(&sql, &[&ids, &values, &tokens]).await?
    } else {
        batch.tx.execute(&sql, &[&ids, &values]).await?
    };
    Ok(updated)
}

/// Keep the envelope and token atomic, while isolating unique violations per row.
pub(super) async fn write_row(
    batch: &batch::Batch<'_, '_>,
    rewrite: &RowRewrite,
) -> anyhow::Result<bool> {
    let id = rewrite.id;
    let value = &rewrite.value;
    let token = rewrite.token.as_deref();
    let field = batch.field;
    let rewrap = batch.action == "rewrap";
    if rewrap {
        batch.tx.batch_execute("SAVEPOINT rewrap_row").await?;
    }
    let row_id = row_id_expression(field, None);
    let result = if let Some((token_column, _)) = field.token {
        let sql = format!(
            "UPDATE {table} SET {column}=$2,{token_column}=$3 WHERE {row_id}=$1",
            table = field.table,
            column = field.column
        );
        batch.tx.execute(&sql, &[&id, &value, &token]).await
    } else {
        let sql = format!(
            "UPDATE {table} SET {column}=$2 WHERE {row_id}=$1",
            table = field.table,
            column = field.column
        );
        batch.tx.execute(&sql, &[&id, &value]).await
    };
    match result {
        Ok(updated) => {
            if rewrap {
                batch
                    .tx
                    .batch_execute("RELEASE SAVEPOINT rewrap_row")
                    .await?;
            }
            Ok(updated > 0)
        }
        Err(error) if rewrap && error.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
            batch
                .tx
                .batch_execute("ROLLBACK TO SAVEPOINT rewrap_row; RELEASE SAVEPOINT rewrap_row")
                .await?;
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}
