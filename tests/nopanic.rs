// Test for the absence of panics using using [`no_panic`]
// Requires a release build, which interferes with the no_alloc tests
// The no_panic attributes therefore have their own flag and is not part of the
// normal build

#[cfg(feature = "_nopanic")]
use no_panic::no_panic;
#[cfg(feature = "_nopanic")]
use url_lite::Url;

#[test]
#[no_panic]
#[cfg(feature = "_nopanic")]
fn test_no_panic() {
    let _ = Url::parse("http://hostname/");
}
