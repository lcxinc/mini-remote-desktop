use std::cmp::Ordering;

#[derive(Debug, Clone, Default)]
pub struct Series {
    pub values_ms: Vec<f64>,
}

#[derive(Debug, Clone, Default)]
pub struct SeriesSummary {
    pub avg: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub std: f64,
    pub jitter: f64,
    pub count: usize,
}

impl Series {
    pub fn push(&mut self, v: f64) {
        if v.is_finite() {
            self.values_ms.push(v);
        }
    }

    pub fn summary(&self) -> SeriesSummary {
        summarize(&self.values_ms)
    }
}

pub fn summarize(values: &[f64]) -> SeriesSummary {
    if values.is_empty() {
        return SeriesSummary::default();
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let n = sorted.len();
    let idx = |q: f64| -> usize {
        let i = ((n as f64 - 1.0) * q).round() as isize;
        i.clamp(0, (n - 1) as isize) as usize
    };
    let avg = sorted.iter().copied().sum::<f64>() / n as f64;
    let var = sorted
        .iter()
        .map(|x| {
            let d = *x - avg;
            d * d
        })
        .sum::<f64>()
        / n as f64;
    let std = var.sqrt();
    let mut jitter_acc = 0.0;
    if n > 1 {
        for w in sorted.windows(2) {
            jitter_acc += (w[1] - w[0]).abs();
        }
    }
    let jitter = if n > 1 {
        jitter_acc / (n as f64 - 1.0)
    } else {
        0.0
    };
    SeriesSummary {
        avg,
        p50: sorted[idx(0.50)],
        p95: sorted[idx(0.95)],
        p99: sorted[idx(0.99)],
        std,
        jitter,
        count: n,
    }
}
