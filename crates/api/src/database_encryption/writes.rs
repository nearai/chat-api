use super::*;
use deadpool_postgres::tokio_postgres::error::SqlState;

/// One atomic replacement of an encrypted value and its optional lookup token.
pub(super) struct RowRewrite {
    pub(super) id: Uuid,
    pub(super) value: String,
    pub(super) token: Option<Vec<u8>>,
}

pub(super) struct BatchWriteResult {
    pub(super) updated: u64,
    pub(super) conflicts: Vec<Uuid>,
}

pub(super) async fn write_batch(
    batch: &batch::Batch<'_, '_>,
    rewrites: &[RowRewrite],
) -> anyhow::Result<BatchWriteResult> {
    if rewrites.is_empty() {
        return Ok(BatchWriteResult {
            updated: 0,
            conflicts: Vec::new(),
        });
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
    if field.token.is_none() {
        return Ok(BatchWriteResult {
            updated: batch.tx.execute(&sql, &[&ids, &values]).await?,
            conflicts: Vec::new(),
        });
    }
    batch.tx.batch_execute("SAVEPOINT token_batch").await?;
    let tokens: Vec<_> = rewrites.iter().map(|row| row.token.as_deref()).collect();
    match batch.tx.execute(&sql, &[&ids, &values, &tokens]).await {
        Ok(updated) => {
            batch
                .tx
                .batch_execute("RELEASE SAVEPOINT token_batch")
                .await?;
            Ok(BatchWriteResult {
                updated,
                conflicts: Vec::new(),
            })
        }
        Err(error) if error.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
            batch
                .tx
                .batch_execute("ROLLBACK TO SAVEPOINT token_batch; RELEASE SAVEPOINT token_batch")
                .await?;
            let mut result = BatchWriteResult {
                updated: 0,
                conflicts: Vec::new(),
            };
            for rewrite in rewrites {
                if write_row(batch, rewrite).await? {
                    result.updated += 1;
                } else {
                    result.conflicts.push(rewrite.id);
                }
            }
            Ok(result)
        }
        Err(error) => {
            batch
                .tx
                .batch_execute("ROLLBACK TO SAVEPOINT token_batch; RELEASE SAVEPOINT token_batch")
                .await?;
            Err(error.into())
        }
    }
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
    batch.tx.batch_execute("SAVEPOINT token_row").await?;
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
            batch
                .tx
                .batch_execute("RELEASE SAVEPOINT token_row")
                .await?;
            Ok(updated > 0)
        }
        Err(error) if error.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
            batch
                .tx
                .batch_execute("ROLLBACK TO SAVEPOINT token_row; RELEASE SAVEPOINT token_row")
                .await?;
            Ok(false)
        }
        Err(error) => {
            batch
                .tx
                .batch_execute("ROLLBACK TO SAVEPOINT token_row; RELEASE SAVEPOINT token_row")
                .await?;
            Err(error.into())
        }
    }
}
