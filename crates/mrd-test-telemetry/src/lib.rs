use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

const TELEMETRY_DIR_ENV: &str = "MRD_TEST_TELEMETRY_DIR";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryRunMetadata {
    pub run_id: String,
    pub scenario_id: String,
    pub status: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_snapshot: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_snapshot: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryMetricSample {
    pub run_id: String,
    pub metric_name: String,
    pub timestamp: u64,
    pub value: f64,
    pub unit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryStageEvent {
    pub stage: String,
    pub status: String,
    pub timestamp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryLogEntry {
    pub run_id: String,
    pub timestamp: u64,
    pub level: String,
    pub source: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryArtifactRecord {
    pub artifact_id: String,
    pub kind: String,
    pub run_id: String,
    pub created_at: u64,
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TelemetryQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_ms: Option<u64>,
    #[serde(default)]
    pub metric_names: Vec<String>,
    #[serde(default)]
    pub log_sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_points: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryMetricPoint {
    pub timestamp: u64,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryMetricAggregation {
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub mean: Option<f64>,
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    pub p99: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryMetricSeries {
    pub metric_name: String,
    pub unit: String,
    pub samples: Vec<TelemetryMetricPoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregation: Option<TelemetryMetricAggregation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TelemetryDiagnostics {
    pub corrupt_rows: usize,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryBundle {
    pub run: Option<TelemetryRunMetadata>,
    pub metrics: HashMap<String, TelemetryMetricSeries>,
    pub events: Vec<TelemetryStageEvent>,
    pub logs: Vec<TelemetryLogEntry>,
    pub artifacts: Vec<TelemetryArtifactRecord>,
    pub diagnostics: TelemetryDiagnostics,
}

#[derive(Debug, Clone)]
pub struct TelemetryStore {
    root: PathBuf,
}

impl TelemetryStore {
    pub fn from_env_or_dir(default_root: impl Into<PathBuf>) -> Self {
        let root = std::env::var_os(TELEMETRY_DIR_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| default_root.into());
        Self::new(root)
    }

    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn upsert_run(&self, metadata: &TelemetryRunMetadata) -> Result<()> {
        let dir = self.run_dir(&metadata.run_id);
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create telemetry run dir {}", dir.display()))?;
        write_json_pretty(&dir.join("metadata.json"), metadata)
    }

    pub fn append_metric(&self, sample: &TelemetryMetricSample) -> Result<()> {
        self.append_jsonl(&sample.run_id, "metrics.jsonl", sample)
    }

    pub fn append_event(&self, run_id: &str, event: &TelemetryStageEvent) -> Result<()> {
        self.append_jsonl(run_id, "events.jsonl", event)
    }

    pub fn append_log(&self, entry: &TelemetryLogEntry) -> Result<()> {
        self.append_jsonl(&entry.run_id, "logs.jsonl", entry)
    }

    pub fn upsert_artifacts(
        &self,
        run_id: &str,
        artifacts: &[TelemetryArtifactRecord],
    ) -> Result<()> {
        let dir = self.run_dir(run_id);
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create telemetry run dir {}", dir.display()))?;
        write_json_pretty(&dir.join("artifacts.json"), artifacts)
    }

    pub fn load_run(&self, run_id: &str) -> Result<Option<TelemetryRunMetadata>> {
        let path = self.run_dir(run_id).join("metadata.json");
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read telemetry metadata {}", path.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse telemetry metadata {}", path.display()))
            .map(Some)
    }

    pub fn list_runs(&self, limit: Option<usize>) -> Result<Vec<TelemetryRunMetadata>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut runs = Vec::new();
        for entry in fs::read_dir(&self.root)
            .with_context(|| format!("failed to read telemetry root {}", self.root.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(run_id) = entry.file_name().to_str() {
                    if let Some(run) = self.load_run(run_id)? {
                        runs.push(run);
                    }
                }
            }
        }
        runs.sort_by_key(|run| std::cmp::Reverse(run.started_at));
        if let Some(limit) = limit {
            runs.truncate(limit);
        }
        Ok(runs)
    }

    pub fn query_bundle(&self, run_id: &str, query: TelemetryQuery) -> Result<TelemetryBundle> {
        let run = self.load_run(run_id)?;
        let mut diagnostics = TelemetryDiagnostics::default();
        let metrics = self.read_metrics(run_id, &query, &mut diagnostics)?;
        let events = self.read_events(run_id, &query, &mut diagnostics)?;
        let logs = self.read_logs(run_id, &query, &mut diagnostics)?;
        let artifacts = self.read_artifacts(run_id)?;

        Ok(TelemetryBundle {
            run,
            metrics,
            events,
            logs,
            artifacts,
            diagnostics,
        })
    }

    fn append_jsonl<T: Serialize>(&self, run_id: &str, file_name: &str, value: &T) -> Result<()> {
        let dir = self.run_dir(run_id);
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create telemetry run dir {}", dir.display()))?;
        let path = dir.join(file_name);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open telemetry jsonl {}", path.display()))?;
        serde_json::to_writer(&mut file, value)
            .with_context(|| format!("failed to serialize telemetry row {}", path.display()))?;
        file.write_all(b"\n")
            .with_context(|| format!("failed to write telemetry row {}", path.display()))
    }

    fn read_metrics(
        &self,
        run_id: &str,
        query: &TelemetryQuery,
        diagnostics: &mut TelemetryDiagnostics,
    ) -> Result<HashMap<String, TelemetryMetricSeries>> {
        let rows: Vec<TelemetryMetricSample> =
            read_jsonl_lossy(&self.run_dir(run_id).join("metrics.jsonl"), diagnostics)?;
        let mut series: HashMap<String, TelemetryMetricSeries> = HashMap::new();
        for row in rows {
            if !matches_time(row.timestamp, query) {
                continue;
            }
            if !query.metric_names.is_empty() && !query.metric_names.contains(&row.metric_name) {
                continue;
            }
            let entry =
                series
                    .entry(row.metric_name.clone())
                    .or_insert_with(|| TelemetryMetricSeries {
                        metric_name: row.metric_name.clone(),
                        unit: row.unit.clone(),
                        samples: Vec::new(),
                        aggregation: None,
                        category: row.category.clone(),
                        display_name: row.display_name.clone(),
                        source: row.source.clone(),
                    });
            entry.samples.push(TelemetryMetricPoint {
                timestamp: row.timestamp,
                value: row.value,
            });
        }
        for entry in series.values_mut() {
            entry.samples.sort_by_key(|sample| sample.timestamp);
            if let Some(max_points) = query.max_points {
                downsample(&mut entry.samples, max_points);
            }
            entry.aggregation = Some(compute_aggregation(&entry.samples));
        }
        Ok(series)
    }

    fn read_events(
        &self,
        run_id: &str,
        query: &TelemetryQuery,
        diagnostics: &mut TelemetryDiagnostics,
    ) -> Result<Vec<TelemetryStageEvent>> {
        let mut rows: Vec<TelemetryStageEvent> =
            read_jsonl_lossy(&self.run_dir(run_id).join("events.jsonl"), diagnostics)?;
        rows.retain(|row| matches_time(row.timestamp, query));
        rows.sort_by_key(|row| row.timestamp);
        Ok(rows)
    }

    fn read_logs(
        &self,
        run_id: &str,
        query: &TelemetryQuery,
        diagnostics: &mut TelemetryDiagnostics,
    ) -> Result<Vec<TelemetryLogEntry>> {
        let mut rows: Vec<TelemetryLogEntry> =
            read_jsonl_lossy(&self.run_dir(run_id).join("logs.jsonl"), diagnostics)?;
        rows.retain(|row| {
            matches_time(row.timestamp, query)
                && (query.log_sources.is_empty() || query.log_sources.contains(&row.source))
        });
        rows.sort_by_key(|row| row.timestamp);
        Ok(rows)
    }

    fn read_artifacts(&self, run_id: &str) -> Result<Vec<TelemetryArtifactRecord>> {
        let path = self.run_dir(run_id).join("artifacts.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read telemetry artifacts {}", path.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse telemetry artifacts {}", path.display()))
    }

    fn run_dir(&self, run_id: &str) -> PathBuf {
        self.root.join(sanitize_run_id(run_id))
    }
}

fn write_json_pretty<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    let mut file =
        File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)
        .with_context(|| format!("failed to serialize {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to finalize {}", path.display()))
}

fn read_jsonl_lossy<T: for<'de> Deserialize<'de>>(
    path: &Path,
    diagnostics: &mut TelemetryDiagnostics,
) -> Result<Vec<T>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut rows = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("failed to read {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<T>(&line) {
            Ok(row) => rows.push(row),
            Err(error) => {
                diagnostics.corrupt_rows += 1;
                diagnostics.warnings.push(format!(
                    "{}:{} ignored corrupt row: {}",
                    path.display(),
                    index + 1,
                    error
                ));
            }
        }
    }
    Ok(rows)
}

fn matches_time(timestamp: u64, query: &TelemetryQuery) -> bool {
    query.start_ms.is_none_or(|start| timestamp >= start)
        && query.end_ms.is_none_or(|end| timestamp <= end)
}

fn compute_aggregation(samples: &[TelemetryMetricPoint]) -> TelemetryMetricAggregation {
    if samples.is_empty() {
        return TelemetryMetricAggregation {
            min: None,
            max: None,
            mean: None,
            p50: None,
            p95: None,
            p99: None,
        };
    }
    let mut values: Vec<f64> = samples.iter().map(|sample| sample.value).collect();
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let last = values.len().saturating_sub(1);
    let sum: f64 = values.iter().sum();
    TelemetryMetricAggregation {
        min: values.first().copied(),
        max: values.last().copied(),
        mean: Some(sum / values.len() as f64),
        p50: Some(values[values.len() / 2]),
        p95: Some(values[((values.len() * 95) / 100).min(last)]),
        p99: Some(values[((values.len() * 99) / 100).min(last)]),
    }
}

fn downsample(samples: &mut Vec<TelemetryMetricPoint>, max_points: usize) {
    if max_points == 0 {
        samples.clear();
        return;
    }
    if samples.len() <= max_points {
        return;
    }
    let step = (samples.len() as f64 / max_points as f64).ceil() as usize;
    let mut reduced: Vec<TelemetryMetricPoint> =
        samples.iter().step_by(step.max(1)).cloned().collect();
    if let (Some(last_original), Some(last_reduced)) = (samples.last(), reduced.last()) {
        if last_original.timestamp != last_reduced.timestamp {
            reduced.push(last_original.clone());
        }
    }
    if reduced.len() > max_points {
        reduced.truncate(max_points);
    }
    *samples = reduced;
}

fn sanitize_run_id(run_id: &str) -> String {
    run_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_store(name: &str) -> TelemetryStore {
        let root =
            std::env::temp_dir().join(format!("mrd-test-telemetry-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        TelemetryStore::new(root)
    }

    #[test]
    fn persists_metrics_logs_and_metadata_across_store_instances() {
        let store = unique_store("persist");
        let root = store.root().to_path_buf();
        store
            .upsert_run(&TelemetryRunMetadata {
                run_id: "run-1".to_string(),
                scenario_id: "e2e.local".to_string(),
                status: "running".to_string(),
                started_at: 1000,
                finished_at: None,
                tags: vec!["local".to_string()],
                config_snapshot: None,
                environment_snapshot: None,
                summary: None,
                classification: None,
            })
            .unwrap();
        store
            .append_metric(&TelemetryMetricSample {
                run_id: "run-1".to_string(),
                metric_name: "capture_fps".to_string(),
                timestamp: 1100,
                value: 143.7,
                unit: "fps".to_string(),
                category: Some("fps".to_string()),
                source: Some("harness".to_string()),
                display_name: Some("Capture FPS".to_string()),
            })
            .unwrap();
        store
            .append_log(&TelemetryLogEntry {
                run_id: "run-1".to_string(),
                timestamp: 1200,
                level: "info".to_string(),
                source: "structured_log".to_string(),
                message: "probe ready".to_string(),
                fields: None,
            })
            .unwrap();

        let reopened = TelemetryStore::new(root);
        let bundle = reopened
            .query_bundle("run-1", TelemetryQuery::default())
            .unwrap();
        assert_eq!(bundle.run.unwrap().scenario_id, "e2e.local");
        assert_eq!(bundle.metrics["capture_fps"].samples[0].value, 143.7);
        assert_eq!(bundle.logs[0].message, "probe ready");
    }

    #[test]
    fn filters_by_time_metric_and_log_source() {
        let store = unique_store("filter");
        store
            .upsert_run(&TelemetryRunMetadata {
                run_id: "run-2".to_string(),
                scenario_id: "matrix".to_string(),
                status: "completed".to_string(),
                started_at: 0,
                finished_at: Some(3000),
                tags: Vec::new(),
                config_snapshot: None,
                environment_snapshot: None,
                summary: None,
                classification: None,
            })
            .unwrap();
        for (name, timestamp, value) in [
            ("capture_fps", 1000, 30.0),
            ("capture_fps", 2000, 60.0),
            ("decode_latency_p95_ms", 2000, 4.0),
        ] {
            store
                .append_metric(&TelemetryMetricSample {
                    run_id: "run-2".to_string(),
                    metric_name: name.to_string(),
                    timestamp,
                    value,
                    unit: if name.ends_with("_ms") { "ms" } else { "fps" }.to_string(),
                    category: None,
                    source: None,
                    display_name: None,
                })
                .unwrap();
        }
        store
            .append_log(&TelemetryLogEntry {
                run_id: "run-2".to_string(),
                timestamp: 2000,
                level: "info".to_string(),
                source: "raw_log".to_string(),
                message: "raw".to_string(),
                fields: None,
            })
            .unwrap();

        let bundle = store
            .query_bundle(
                "run-2",
                TelemetryQuery {
                    start_ms: Some(1500),
                    metric_names: vec!["capture_fps".to_string()],
                    log_sources: vec!["structured_log".to_string()],
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(bundle.metrics.len(), 1);
        assert_eq!(bundle.metrics["capture_fps"].samples.len(), 1);
        assert!(bundle.logs.is_empty());
    }

    #[test]
    fn ignores_corrupt_jsonl_rows_and_reports_diagnostics() {
        let store = unique_store("corrupt");
        store
            .upsert_run(&TelemetryRunMetadata {
                run_id: "bad/run".to_string(),
                scenario_id: "matrix".to_string(),
                status: "running".to_string(),
                started_at: 0,
                finished_at: None,
                tags: Vec::new(),
                config_snapshot: None,
                environment_snapshot: None,
                summary: None,
                classification: None,
            })
            .unwrap();
        let metrics_path = store.root().join("bad_run").join("metrics.jsonl");
        fs::write(
            &metrics_path,
            concat!(
                "{\"run_id\":\"bad/run\",\"metric_name\":\"capture_fps\",\"timestamp\":1,\"value\":1.0,\"unit\":\"fps\"}\n",
                "not-json\n"
            ),
        )
        .unwrap();
        let bundle = store
            .query_bundle("bad/run", TelemetryQuery::default())
            .unwrap();
        assert_eq!(bundle.metrics["capture_fps"].samples.len(), 1);
        assert_eq!(bundle.diagnostics.corrupt_rows, 1);
    }
}
