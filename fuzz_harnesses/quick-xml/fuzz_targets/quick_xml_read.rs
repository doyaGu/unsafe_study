#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use quick_xml::{events::Event, reader::Reader};

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::from_reader(Cursor::new(data));
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut scratch = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(start)) => {
                let end = start.to_end().into_owned();
                let _ = end.name().as_ref().len();
                let _ = reader.read_to_end_into(end.name(), &mut scratch);
                scratch.clear();
            }
            Ok(Event::Empty(start)) => {
                let _ = start.name().as_ref().len();
            }
            Ok(Event::Text(text)) => {
                let _ = text.decode();
            }
            Ok(Event::Comment(comment)) => {
                let _ = comment.decode();
            }
            Ok(Event::CData(cdata)) => {
                let _ = cdata.escape();
            }
            Ok(Event::Decl(decl)) => {
                let _ = decl.version();
                let _ = decl.encoding();
                let _ = decl.standalone();
            }
            Ok(Event::DocType(doctype)) => {
                let _ = doctype.decode();
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
});