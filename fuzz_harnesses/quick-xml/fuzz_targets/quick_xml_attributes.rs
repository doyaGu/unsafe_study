#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use quick_xml::{events::BytesStart, events::Event, reader::Reader};

fn inspect_attributes(start: &BytesStart<'_>) {
    let mut attrs = start.attributes();
    attrs.with_checks(false);
    for attr in attrs {
        match attr {
            Ok(attr) => {
                let _ = attr.key.as_ref().len();
                let _ = attr.unescape_value();
            }
            Err(error) => {
                let _ = format!("{error:?}").len();
                break;
            }
        }
    }

    let mut html_attrs = start.html_attributes();
    html_attrs.with_checks(false);
    for attr in html_attrs {
        match attr {
            Ok(attr) => {
                let _ = attr.key.as_ref().len();
                let _ = attr.unescape_value();
            }
            Err(error) => {
                let _ = format!("{error:?}").len();
                break;
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::from_reader(Cursor::new(data));
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(start)) | Ok(Event::Empty(start)) => {
                inspect_attributes(&start);
            }
            Ok(Event::Decl(decl)) => {
                let _ = decl.version();
                let _ = decl.encoding();
                let _ = decl.standalone();
            }
            Ok(Event::PI(pi)) => {
                for attr in pi.attributes() {
                    match attr {
                        Ok(attr) => {
                            let _ = attr.key.as_ref().len();
                            let _ = attr.unescape_value();
                        }
                        Err(error) => {
                            let _ = format!("{error:?}").len();
                            break;
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
});