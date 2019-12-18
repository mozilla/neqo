// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use chrono::{DateTime, Utc};

use std::time::SystemTime;

use qlog::{CommonFields, Configuration, TimeUnits, Trace, VantagePoint, VantagePointType};

use crate::Role;

#[must_use]
pub fn new_trace(role: Role) -> qlog::Trace {
    let role_str = match role {
        Role::Client => "client",
        Role::Server => "server",
    };

    Trace {
        vantage_point: VantagePoint {
            name: Some(format!("neqo-{}", role_str)),
            ty: VantagePointType::Server,
            flow: None,
        },
        title: Some(format!("neqo-{} trace", role_str)),
        description: Some("Example qlog trace description".to_string()),
        configuration: Some(Configuration {
            time_offset: Some("0".into()),
            time_units: Some(TimeUnits::Us),
            original_uris: None,
        }),
        common_fields: Some(CommonFields {
            group_id: None,
            protocol_type: None,
            reference_time: Some({
                let system_time = SystemTime::now();
                let datetime: DateTime<Utc> = system_time.into();
                datetime.to_rfc3339()
            }),
        }),
        event_fields: vec![
            "relative_time".to_string(),
            "category".to_string(),
            "event".to_string(),
            "data".to_string(),
        ],
        events: Vec::new(),
    }
}
