use super::*;
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Mode {
    DryRun,
    Execute,
    Verify,
}

#[derive(Deserialize)]
pub struct CreateJobRequest {
    pub(super) mode: Mode,
    pub(super) scope: Scope,
    #[serde(default = "default_batch")]
    pub(super) batch_size: i64,
    pub(super) max_rows: Option<i64>,
    pub(super) actions: Vec<String>,
    #[serde(default, deserialize_with = "batch_delay")]
    pub(super) batch_delay_ms: u64,
}

pub(super) fn default_batch() -> i64 {
    100
}

pub(super) fn validate_actions(
    mode: &Mode,
    actions: &[String],
) -> Result<(), (StatusCode, Json<Value>)> {
    let valid = match mode {
        Mode::Verify => actions == ["verify"],
        Mode::DryRun | Mode::Execute => actions == ["encrypt"] || actions == ["rewrap"],
    };
    if valid {
        Ok(())
    } else {
        Err(bad("actions do not match mode"))
    }
}
