use async_trait::async_trait;
use mrd_relay_agent::metrics::{
    parse_native_coturn_scrape, CoturnMetrics, MetricsError, MetricsLimits, MetricsPort,
    NativeCoturnScrape, NativeCoturnScrapePort, PlatformMetrics, TargetTrafficPort,
    TrafficCounterSample, TrafficRateNormalizer,
};
use mrd_relay_agent::platform::PlatformTrafficSample;

#[test]
fn native_coturn_scrape_sums_bounded_labeled_gauges_without_calling_counters_bps() {
    let fixture = include_bytes!("fixtures/coturn-4.17.2-prometheus.txt");
    let scrape = parse_native_coturn_scrape(fixture, MetricsLimits::default()).unwrap();

    assert_eq!(scrape.active_allocations, 12);
    assert_eq!(
        scrape.errors_total, 8,
        "normal 401 challenge request/response counters are not node errors"
    );
    assert_eq!(scrape.finished_sent_bytes, 3_145_728);
    assert_eq!(scrape.finished_received_bytes, 524_288);
}

#[test]
fn target_counters_require_two_monotonic_samples_in_the_same_epoch() {
    let mut normalizer = TrafficRateNormalizer::default();
    assert_eq!(
        normalizer.observe(TrafficCounterSample {
            generation: 8,
            counter_epoch: "invocation-a".into(),
            total_ingress_bytes: 1_000,
            total_egress_bytes: 2_000,
            measurement_monotonic_ns: 1_000_000_000,
        }),
        Ok(None)
    );
    let rate = normalizer
        .observe(TrafficCounterSample {
            generation: 8,
            counter_epoch: "invocation-a".into(),
            total_ingress_bytes: 2_000,
            total_egress_bytes: 4_000,
            measurement_monotonic_ns: 2_000_000_000,
        })
        .unwrap()
        .unwrap();
    assert_eq!(rate.current_ingress_bps, 8_000);
    assert_eq!(rate.current_egress_bps, 16_000);
}

#[test]
fn target_counter_reset_or_epoch_change_is_degraded_and_reseeds_baseline() {
    let mut normalizer = TrafficRateNormalizer::default();
    let baseline = TrafficCounterSample {
        generation: 8,
        counter_epoch: "invocation-a".into(),
        total_ingress_bytes: 10_000,
        total_egress_bytes: 20_000,
        measurement_monotonic_ns: 1_000_000_000,
    };
    assert_eq!(normalizer.observe(baseline), Ok(None));
    assert_eq!(
        normalizer.observe(TrafficCounterSample {
            generation: 8,
            counter_epoch: "invocation-a".into(),
            total_ingress_bytes: 9_999,
            total_egress_bytes: 20_001,
            measurement_monotonic_ns: 2_000_000_000,
        }),
        Err(MetricsError::CounterReset)
    );
    assert_eq!(
        normalizer.observe(TrafficCounterSample {
            generation: 9,
            counter_epoch: "invocation-b".into(),
            total_ingress_bytes: 1,
            total_egress_bytes: 1,
            measurement_monotonic_ns: 3_000_000_000,
        }),
        Ok(None)
    );
}

#[test]
fn native_scrape_rejects_unknown_labels_cardinality_non_finite_and_fractional_counts() {
    let limits = MetricsLimits::default();
    for invalid in [
        "turn_total_allocations{tenant=\"secret\"} 1\n",
        "turn_total_allocations{type=\"UDP\"} NaN\n",
        "turn_total_allocations{type=\"UDP\"} +Inf\n",
        "turn_total_allocations{type=\"UDP\"} 1.5\n",
        "turn_total_allocations{type=\"UDP\",type=\"TCP\"} 1\n",
        "turn_total_allocations{type=\"NOT-A-SOCKET-TYPE\"} 1\n",
    ] {
        assert_eq!(
            parse_native_coturn_scrape(invalid.as_bytes(), limits),
            Err(MetricsError::Invalid)
        );
    }

    let tight = MetricsLimits {
        max_fields: 2,
        ..limits
    };
    let too_many = "turn_total_allocations{type=\"UDP\"} 1\nturn_total_allocations{type=\"TCP\"} 1\nturn_total_allocations{type=\"TLS/TCP\"} 1\n";
    assert!(matches!(
        parse_native_coturn_scrape(too_many.as_bytes(), tight),
        Err(MetricsError::Invalid | MetricsError::TooLarge)
    ));
}

struct FakeNativeScrape(NativeCoturnScrape);

#[async_trait]
impl NativeCoturnScrapePort for FakeNativeScrape {
    async fn scrape(&self) -> Result<NativeCoturnScrape, MetricsError> {
        Ok(self.0.clone())
    }
}

struct FailingNativeScrape;

#[async_trait]
impl NativeCoturnScrapePort for FailingNativeScrape {
    async fn scrape(&self) -> Result<NativeCoturnScrape, MetricsError> {
        Err(MetricsError::Unavailable)
    }
}

struct FakeTargetTraffic(PlatformTrafficSample);

#[async_trait]
impl TargetTrafficPort for FakeTargetTraffic {
    async fn collect_target_traffic(&self) -> Result<PlatformTrafficSample, MetricsError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn production_metrics_combines_native_allocations_with_target_network_counters() {
    let scrape = FakeNativeScrape(NativeCoturnScrape {
        active_allocations: 4,
        finished_sent_bytes: 9_999_999,
        finished_received_bytes: 8_888_888,
        errors_total: 3,
    });
    let traffic = FakeTargetTraffic(PlatformTrafficSample {
        generation: 8,
        active_allocations: 4,
        current_ingress_bps: 64_000,
        current_egress_bps: 128_000,
    });
    let metrics = PlatformMetrics::new(scrape, traffic);

    assert_eq!(
        metrics.collect().await.unwrap(),
        CoturnMetrics {
            active_allocations: 4,
            current_ingress_bps: 64_000,
            current_egress_bps: 128_000,
            errors_total: 3,
        }
    );
}

#[tokio::test]
async fn production_metrics_uses_broker_allocations_when_native_scrape_is_concurrently_stale() {
    let scrape = FakeNativeScrape(NativeCoturnScrape {
        active_allocations: 5,
        finished_sent_bytes: 9_999_999,
        finished_received_bytes: 8_888_888,
        errors_total: 7,
    });
    let traffic = FakeTargetTraffic(PlatformTrafficSample {
        generation: 8,
        active_allocations: 4,
        current_ingress_bps: 64_000,
        current_egress_bps: 128_000,
    });
    let metrics = PlatformMetrics::new(scrape, traffic);

    assert_eq!(
        metrics.collect().await.unwrap(),
        CoturnMetrics {
            active_allocations: 4,
            current_ingress_bps: 64_000,
            current_egress_bps: 128_000,
            errors_total: 7,
        }
    );
}

#[tokio::test]
async fn production_metrics_still_fails_closed_when_native_diagnostics_are_unavailable() {
    let traffic = FakeTargetTraffic(PlatformTrafficSample {
        generation: 8,
        active_allocations: 4,
        current_ingress_bps: 64_000,
        current_egress_bps: 128_000,
    });
    let metrics = PlatformMetrics::new(FailingNativeScrape, traffic);

    assert_eq!(metrics.collect().await, Err(MetricsError::Unavailable));
}
