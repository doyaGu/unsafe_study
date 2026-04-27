#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use quick_xml::{events::Event, reader::NsReader};

fuzz_target!(|data: &[u8]| {
    let mut reader = NsReader::from_reader(Cursor::new(data));
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut scratch = Vec::new();

    loop {
        match reader.read_resolved_event_into(&mut buf) {
            Ok((resolved, Event::Start(start))) => {
                let _ = format!("{resolved:?}").len();
                let _ = reader.resolver().bindings().count();
                let _ = start.local_name().as_ref().len();
                let _ = start.attributes().has_nil(reader.resolver());

                let end = start.to_end().into_owned();
                let _ = reader.read_to_end_into(end.name(), &mut scratch);
                scratch.clear();
            }
            Ok((resolved, Event::Empty(start))) => {
                let _ = format!("{resolved:?}").len();
                let _ = reader.resolver().bindings().count();
                let _ = start.local_name().as_ref().len();
                let _ = start.attributes().has_nil(reader.resolver());
            }
            Ok((resolved, Event::Text(text))) => {
                let _ = format!("{resolved:?}").len();
                let _ = text.decode();
            }
            Ok((_, Event::Eof)) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
});