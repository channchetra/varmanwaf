//! Capture of raw ACME certificate-issuance logs on the agent side.
//!
//! Pingap's ACME machinery emits tracing events under the `pingap::acme`
//! target. An [`AcmeCaptureLayer`] installed on the global tracing subscriber
//! siphons those events into a bounded in-memory buffer, which the
//! control-plane client periodically ships through the `ShipCertEvents` RPC.
//! This is what surfaces the original issuance logs on the management panel,
//! letting administrators diagnose certificate problems.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use prost_types::Timestamp;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

use pingwaf_proto::control_plane as proto;

/// Maximum number of buffered events. Oldest entries are dropped once full so
/// a stalled shipper can never block the tracing hot path or grow memory.
const CAPACITY: usize = 1024;

/// Target prefix identifying ACME events emitted by pingap.
const ACME_TARGET_PREFIX: &str = "pingap::acme";

static CERT_EVENT_BUFFER: OnceLock<CertEventBuffer> = OnceLock::new();

/// Global capture buffer, created on first use.
pub fn cert_event_buffer() -> &'static CertEventBuffer {
    CERT_EVENT_BUFFER.get_or_init(CertEventBuffer::new)
}

/// Bounded FIFO of raw certificate events captured from tracing.
pub struct CertEventBuffer {
    entries: Mutex<VecDeque<proto::CertEventEntry>>,
}

impl CertEventBuffer {
    fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(CAPACITY)),
        }
    }

    fn push(&self, entry: proto::CertEventEntry) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if entries.len() >= CAPACITY {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Take all buffered events, prefixing each with the agent id.
    pub fn drain(&self, agent_id: &str) -> Vec<proto::CertEventEntry> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries
            .drain(..)
            .map(|mut entry| {
                entry.agent_id = agent_id.to_string();
                entry
            })
            .collect()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

/// `tracing_subscriber::Layer` that copies every event whose target starts
/// with `pingap::acme` into the global [`CertEventBuffer`].
///
/// [`Layer::enabled`] is deliberately not overridden: per-layer `enabled`
/// results are combined across the whole subscriber stack, so returning
/// `false` here would disable non-ACME callsites for the other layers too.
pub struct AcmeCaptureLayer;

impl<S: Subscriber> Layer<S> for AcmeCaptureLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if !event.metadata().target().starts_with(ACME_TARGET_PREFIX) {
            return;
        }
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let Some(message) = visitor.message else {
            return;
        };
        if message.is_empty() {
            return;
        }
        cert_event_buffer().push(proto::CertEventEntry {
            agent_id: String::new(),
            site_id: String::new(),
            certificate_id: String::new(),
            event_type: "acme_raw".to_string(),
            level: event.metadata().level().as_str().to_string(),
            target: event.metadata().target().to_string(),
            message,
            timestamp: Some(Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
        });
    }
}

/// Visitor that extracts the `message` field of a tracing event.
#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl Visit for MessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }

    fn record_error(
        &mut self,
        field: &Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex as StdMutex, OnceLock};

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn push_drops_oldest_when_full() {
        let _guard = test_lock();
        let buffer = CertEventBuffer::new();
        for i in 0..CAPACITY + 100 {
            buffer.push(proto::CertEventEntry {
                agent_id: String::new(),
                site_id: String::new(),
                certificate_id: String::new(),
                event_type: "acme_raw".to_string(),
                level: "INFO".to_string(),
                target: ACME_TARGET_PREFIX.to_string(),
                message: format!("event {i}"),
                timestamp: None,
            });
        }
        let drained = buffer.drain("agent-1");
        assert_eq!(drained.len(), CAPACITY);
        assert_eq!(drained[0].message, "event 100");
        assert_eq!(
            drained.last().unwrap().message,
            format!("event {}", CAPACITY + 99)
        );
        assert!(drained.iter().all(|entry| entry.agent_id == "agent-1"));
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn layer_captures_acme_events_only() {
        let _guard = test_lock();
        cert_event_buffer().drain("");

        use tracing_subscriber::prelude::*;
        let subscriber = tracing_subscriber::registry().with(AcmeCaptureLayer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "pingap::acme", "order created for example.com");
            tracing::warn!(target: "pingap::acme", "challenge failed: dns timeout");
            tracing::info!(target: "pingap::other", "unrelated event");
        });

        let drained = cert_event_buffer().drain("agent-1");
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].message, "order created for example.com");
        assert_eq!(drained[0].level, "INFO");
        assert_eq!(drained[0].event_type, "acme_raw");
        assert_eq!(drained[0].target, "pingap::acme");
        assert_eq!(drained[1].level, "WARN");
        assert_eq!(drained[1].message, "challenge failed: dns timeout");
    }
}
