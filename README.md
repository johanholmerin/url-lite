# url-lite

Port of the URL parser from
[nodejs/http-parser](https://github.com/nodejs/http-parser) to Rust

## Features

- `#[no_std]`
- No heap allocations, returns a struct of `&str`
- Never panics(tested by [dtolnay/no-panic](https://github.com/dtolnay/no-panic))

## Installation

```sh
cargo add url_lite
```

## Example

```rust
use url_lite::{Url, ParseError};

// Note that ParseError doesn't implement the Error trait unless the `unstable`
// feature is enabled
assert!(Url::parse("not-an-url") == Err(ParseError::Invalid))

let input = "https://usr:pass@example.com:8080/some%20path?foo=bar#zzz";
let url = Url::parse(input).expect("Invalid URL");

assert_eq!(url.schema, Some("https"));
assert_eq!(url.host, Some("example.com"));
assert_eq!(url.port, Some("8080"));
assert_eq!(url.path, Some("/some%20path"));
assert_eq!(url.query, Some("foo=bar"));
assert_eq!(url.fragment, Some("zzz"));
assert_eq!(url.userinfo, Some("usr:pass"));
```

## Features

- `unstable` - Implements
  [`core::error::Error`](https://doc.rust-lang.org/core/error/trait.Error.html)
  for `ParseError`. Requires nightly due to
  [error_in_core](https://doc.rust-lang.org/unstable-book/library-features/error-in-core.html)

## Caveats

Although this is a port of the URL parser from http-parser and it passes all
the tests, it has not been used in production. It is also not a generic parser,
may not support all URLs, only returns slices, and performs no decoding.

If you need a robust URL parser and are okay with std/alloc dependency, use
[servo/rust-url](https://crates.io/crates/url) instead.
