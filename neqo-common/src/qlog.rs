// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    fmt,
    path::{Path, PathBuf},
    rc::Rc,
};

use qlog::{
    self, streamer::QlogStreamer, CommonFields, Configuration, TraceSeq, VantagePoint,
    VantagePointType,
};

use crate::Role;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Default)]
pub struct NeqoQlog {
    inner: Rc<RefCell<Option<NeqoQlogShared>>>,
}

pub struct NeqoQlogShared {
    qlog_path: PathBuf,
    streamer: QlogStreamer,
}

impl NeqoQlog {
    /// Create an enabled `NeqoQlog` configuration.
    /// # Errors
    ///
    /// Will return `qlog::Error` if cannot write to the new log.
    pub fn enabled(
        mut streamer: QlogStreamer,
        qlog_path: impl AsRef<Path>,
    ) -> Result<Self, qlog::Error> {
        streamer.start_log()?;

        Ok(Self {
            inner: Rc::new(RefCell::new(Some(NeqoQlogShared {
                streamer,
                qlog_path: qlog_path.as_ref().to_owned(),
            }))),
        })
    }

    /// Create a disabled `NeqoQlog` configuration.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// If logging enabled, closure may generate an event to be logged.
    pub fn add_event<F>(&mut self, f: F)
    where
        F: FnOnce() -> Option<qlog::events::Event>,
    {
        self.add_event_with_stream(|s| {
            if let Some(evt) = f() {
                s.add_event(evt)?;
            }
            Ok(())
        });
    }

    /// If logging enabled, closure may generate an event to be logged.
    pub fn add_event_data<F>(&mut self, f: F)
    where
        F: FnOnce() -> Option<qlog::events::EventData>,
    {
        self.add_event_with_stream(|s| {
            if let Some(ev_data) = f() {
                s.add_event_data_now(ev_data)?;
            }
            Ok(())
        });
    }

    /// If logging enabled, closure is given the Qlog stream to write events and
    /// frames to.
    pub fn add_event_with_stream<F>(&mut self, f: F)
    where
        F: FnOnce(&mut QlogStreamer) -> Result<(), qlog::Error>,
    {
        if let Some(inner) = self.inner.borrow_mut().as_mut() {
            if let Err(e) = f(&mut inner.streamer) {
                crate::do_log!(
                    ::log::Level::Error,
                    "Qlog event generation failed with error {}; closing qlog.",
                    e
                );
                *self.inner.borrow_mut() = None;
            }
        }
    }
}

impl fmt::Debug for NeqoQlogShared {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NeqoQlog writing to {}", self.qlog_path.display())
    }
}

impl Drop for NeqoQlogShared {
    fn drop(&mut self) {
        if let Err(e) = self.streamer.finish_log() {
            crate::do_log!(::log::Level::Error, "Error dropping NeqoQlog: {}", e);
        }
    }
}

#[must_use]
pub fn new_trace(role: Role) -> qlog::TraceSeq {
    TraceSeq {
        vantage_point: VantagePoint {
            name: Some(format!("neqo-{role}")),
            ty: match role {
                Role::Client => VantagePointType::Client,
                Role::Server => VantagePointType::Server,
            },
            flow: None,
        },
        title: Some(format!("neqo-{role} trace")),
        description: Some("Example qlog trace description".to_string()),
        configuration: Some(Configuration {
            time_offset: Some(0.0),
            original_uris: None,
        }),
        common_fields: Some(CommonFields {
            group_id: None,
            protocol_type: None,
            reference_time: {
                // It is better to allow this than deal with a conversion from i64 to f64.
                // We can't do the obvious two-step conversion with f64::from(i32::try_from(...)),
                // because that overflows earlier than is ideal.  This should be fine for a while.
                #[allow(clippy::cast_precision_loss)]
                Some(time::OffsetDateTime::now_utc().unix_timestamp() as f64)
            },
            time_format: Some("relative".to_string()),
        }),
    }
}

#[cfg(test)]
mod test {
    use super::{new_trace, NeqoQlog};
    use crate::Role;
    use qlog::{
        events::{Event, EventImportance},
        streamer::QlogStreamer,
    };
    use std::io::Cursor;

    const EV_DATA: qlog::events::EventData =
        qlog::events::EventData::SpinBitUpdated(qlog::events::connectivity::SpinBitUpdated {
            state: true,
        });

    const EXPECTED_LOG_HEADER: &str = "\u{1e}{\"qlog_version\":\"0.3\",\"qlog_format\":\"JSON-SEQ\",\"trace\":{\"vantage_point\":{\"name\":\"neqo-Client\",\"type\":\"client\"},\"title\":\"neqo-Client trace\",\"description\":\"Example qlog trace description\",\"configuration\":{\"time_offset\":0.0},\"common_fields\":{\"reference_time\":0.0,\"time_format\":\"relative\"}}}\n";
    const EXPECTED_LOG_EVENT: &str = "\u{1e}{\"time\":0.0,\"name\":\"connectivity:spin_bit_updated\",\"data\":{\"state\":true}}\n";

    fn new_neqo_qlog() -> NeqoQlog {
        let mut trace = new_trace(Role::Client);
        // Set reference time to 0.0 for testing.
        trace.common_fields.as_mut().unwrap().reference_time = Some(0.0);

        let streamer = QlogStreamer::new(
            qlog::QLOG_VERSION.to_string(),
            None,
            None,
            None,
            std::time::Instant::now(),
            trace,
            EventImportance::Base,
            Box::new(Cursor::new(Vec::new())),
        );
        let log = NeqoQlog::enabled(streamer, "");
        assert!(log.is_ok());
        log.unwrap()
    }

    fn log_contents(log: &NeqoQlog) -> String {
        // TODO: Figure out a way to make this less ugly.
        #[allow(clippy::borrowed_box)]
        let w: &Box<std::io::Cursor<Vec<u8>>> = unsafe {
            #[allow(clippy::transmute_ptr_to_ptr)]
            std::mem::transmute(log.inner.borrow_mut().as_mut().unwrap().streamer.writer())
        };
        String::from_utf8(w.as_ref().get_ref().clone()).unwrap()
    }

    #[test]
    fn test_new_neqo_qlog() {
        let log = new_neqo_qlog();
        assert_eq!(log_contents(&log), EXPECTED_LOG_HEADER);
    }

    #[test]
    fn test_add_event() {
        let mut log = new_neqo_qlog();
        log.add_event(|| Some(Event::with_time(1.1, EV_DATA)));
        assert_eq!(
            log_contents(&log),
            format!(
                "{EXPECTED_LOG_HEADER}{}",
                EXPECTED_LOG_EVENT.replace("\"time\":0.0,", "\"time\":1.1,")
            )
        );
    }
}
