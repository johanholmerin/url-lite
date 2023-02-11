#![no_main]

use libfuzzer_sys::fuzz_target;
use url_lite::Url;

fuzz_target!(|data: &[u8]| {
    if let Ok(utf8) = std::str::from_utf8(data) {
        let _ = Url::parse(utf8);
        let _ = Url::parse_connect(utf8);
    }
});
