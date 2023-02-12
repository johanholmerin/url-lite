/*!
Port of the URL parser from
[nodejs/http-parser](https://github.com/nodejs/http-parser) to Rust

# Examples

## Invalid input

```rust
use url_lite::{Url, ParseError};

// Note that ParseError doesn't implement the Error trait unless the `unstable`
// feature is enabled
assert!(Url::parse("not-an-url") == Err(ParseError::Invalid))
```

## Valid input

```rust
use url_lite::Url;

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

# Feature: `unstable`

Implements [`core::error::Error`] for [`ParseError`]. Requires nightly due to
[`error_in_core`](https://doc.rust-lang.org/unstable-book/library-features/error-in-core.html)

# Caveats

Although this is a port of the URL parser from http-parser and it passes all
the tests, it has not been used in production. It is also not a generic parser,
may not support all URLs, only returns slices, and performs no decoding.

If you need a robust URL parser and are okay with std/alloc dependency, use
[servo/rust-url](https://crates.io/crates/url) instead.

*/

#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(feature = "unstable", feature(error_in_core))]

use core::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    InvalidConnect,
    EmptyInput,
    Whitespace,
    NoHost,
    Invalid,
}

impl fmt::Display for ParseError {
    #[cfg(not(tarpaulin_include))]
    #[cfg_attr(feature = "_nopanic", no_panic::no_panic)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidConnect => {
                write!(f, "CONNECT requests can only contain \"hostname:port\"")
            }
            ParseError::EmptyInput => write!(f, "Empty input"),
            ParseError::Whitespace => write!(f, "Whitespace"),
            ParseError::NoHost => {
                write!(f, "host must be present if there is a schema")
            }
            ParseError::Invalid => write!(f, "Invalid URL"),
        }
    }
}

#[cfg(feature = "unstable")]
impl core::error::Error for ParseError {}

#[derive(Debug, PartialEq, Eq)]
enum State {
    SchemaSlash,
    SchemaSlashSlash,
    ServerStart,
    QueryStringStart,
    FragmentStart,
    Schema,
    ServerWithAt,
    Server,
    Path,
    QueryString,
    Fragment,
}

#[derive(Debug, PartialEq, Eq)]
enum UrlFields {
    Schema,
    Host,
    Path,
    Query,
    Fragment,
}

#[derive(Debug, PartialEq, Eq)]
/// A parsed URL
pub struct Url<'a> {
    pub schema: Option<&'a str>,
    pub host: Option<&'a str>,
    pub port: Option<&'a str>,
    pub path: Option<&'a str>,
    pub query: Option<&'a str>,
    pub fragment: Option<&'a str>,
    pub userinfo: Option<&'a str>,
}

impl<'a> Url<'a> {
    #[cfg_attr(feature = "_nopanic", no_panic::no_panic)]
    /// Parse a URL from a string
    ///
    /// # Examples
    ///
    /// ```rust
    /// use url_lite::Url;
    /// # use url_lite::ParseError;
    ///
    /// # fn run() -> Result<(), ParseError> {
    /// let url = Url::parse("http://example.com").expect("Invalid URL");
    /// # Ok(())
    /// # }
    /// # run().unwrap();
    /// ```
    pub fn parse(buf: &'a str) -> Result<Url<'a>, ParseError> {
        parse_url(buf, false)
    }

    /// Parse as a HTTP CONNECT method URL
    ///
    /// Will return an error if the URL contains anything other than hostname
    /// and port
    pub fn parse_connect(buf: &'a str) -> Result<Url<'a>, ParseError> {
        parse_url(buf, true)
    }
}

#[cfg_attr(feature = "_nopanic", no_panic::no_panic)]
fn parse_url(buf: &str, is_connect: bool) -> Result<Url, ParseError> {
    if buf.is_empty() {
        return Err(ParseError::EmptyInput);
    }

    let mut url = Url {
        schema: None,
        host: None,
        port: None,
        path: None,
        query: None,
        fragment: None,
        userinfo: None,
    };

    let mut state = State::ServerStart;
    let mut old_uf: Option<UrlFields> = None;
    let mut found_at = false;

    let mut len = 0;
    let mut off = 0;

    for (i, p) in buf.chars().enumerate() {
        let uf: UrlFields;

        if p.is_whitespace() {
            return Err(ParseError::Whitespace);
        }

        if i == 0 && !is_connect {
            state = parse_url_start(p)?;
        } else {
            state = parse_url_char(state, p)?;
        }

        // Figure out the next field that we're operating on
        match state {
            // Skip delimeters
            State::SchemaSlash
            | State::SchemaSlashSlash
            | State::ServerStart
            | State::QueryStringStart
            | State::FragmentStart => {
                continue;
            }
            State::Schema => {
                uf = UrlFields::Schema;
            }
            State::ServerWithAt => {
                found_at = true;
                uf = UrlFields::Host;
            }
            State::Server => {
                uf = UrlFields::Host;
            }
            State::Path => {
                uf = UrlFields::Path;
            }
            State::QueryString => {
                uf = UrlFields::Query;
            }
            State::Fragment => {
                uf = UrlFields::Fragment;
            }
        }

        off += 1;
        len += 1;

        // Nothing's changed; soldier on
        if old_uf.as_ref() == Some(&uf) {
            continue;
        }

        if let Some(old_uf) = old_uf {
            let value =
                Some(buf.get(off - len..off).ok_or(ParseError::Invalid)?);
            set_url_field(&old_uf, &mut url, value)
        }
        old_uf = Some(uf);
        len = 0;
        off = i;
    }

    if let Some(old_uf) = old_uf {
        let value =
            Some(buf.get(off - len..off + 1).ok_or(ParseError::Invalid)?);
        set_url_field(&old_uf, &mut url, value)
    }

    // host must be present if there is a schema
    // parsing http:///toto will fail
    if url.schema.is_some() && url.host.is_none() {
        return Err(ParseError::NoHost);
    }

    if let Some(host_buf) = url.host.take() {
        url.host = None;

        let mut host_state = if found_at {
            HttpHostState::UserinfoStart
        } else {
            HttpHostState::HostStart
        };

        let mut off = 0;
        let mut len = 0;

        for (i, p) in host_buf.chars().enumerate() {
            let new_host_state = parse_host_char(&host_state, p)?;

            match new_host_state {
                HttpHostState::Host => {
                    if host_state != HttpHostState::Host {
                        off = i;
                        len = 0;
                    }
                    len += 1;
                    url.host = Some(
                        host_buf
                            .get(off..off + len)
                            .ok_or(ParseError::Invalid)?,
                    );
                }
                HttpHostState::Hostv6 => {
                    if host_state != HttpHostState::Hostv6 {
                        off = i;
                    }
                    len += 1;
                    url.host = Some(
                        host_buf
                            .get(off..off + len)
                            .ok_or(ParseError::Invalid)?,
                    );
                }
                HttpHostState::Hostv6ZoneStart | HttpHostState::Hostv6Zone => {
                    len += 1;
                    url.host = Some(
                        host_buf
                            .get(off..off + len)
                            .ok_or(ParseError::Invalid)?,
                    );
                }
                HttpHostState::HostPort => {
                    if host_state != HttpHostState::HostPort {
                        off = i;
                        len = 0;
                    }
                    len += 1;
                    url.port = Some(
                        host_buf
                            .get(off..off + len)
                            .ok_or(ParseError::Invalid)?,
                    );
                }
                HttpHostState::Userinfo => {
                    if host_state != HttpHostState::Userinfo {
                        off = i;
                        len = 0;
                    }
                    len += 1;
                    url.userinfo = Some(
                        host_buf
                            .get(off..off + len)
                            .ok_or(ParseError::Invalid)?,
                    );
                }
                _ => {}
            }
            host_state = new_host_state;
        }

        // Make sure we don't end somewhere unexpected
        match host_state {
            HttpHostState::HostStart
            | HttpHostState::Hostv6Start
            | HttpHostState::Hostv6
            | HttpHostState::Hostv6ZoneStart
            | HttpHostState::Hostv6Zone
            | HttpHostState::HostPortStart
            | HttpHostState::Userinfo
            | HttpHostState::UserinfoStart => {
                return Err(ParseError::Invalid);
            }
            _ => {}
        }
    }

    if is_connect
        && (url.schema.is_some()
            || url.path.is_some()
            || url.query.is_some()
            || url.fragment.is_some()
            || url.userinfo.is_some())
    {
        return Err(ParseError::InvalidConnect);
    }

    Ok(url)
}

#[cfg_attr(feature = "_nopanic", no_panic::no_panic)]
fn set_url_field<'a>(
    uf: &UrlFields,
    mut url: &mut Url<'a>,
    value: Option<&'a str>,
) {
    match uf {
        UrlFields::Schema => url.schema = value,
        UrlFields::Host => url.host = value,
        UrlFields::Path => url.path = value,
        UrlFields::Query => url.query = value,
        UrlFields::Fragment => url.fragment = value,
    };
}

#[cfg_attr(feature = "_nopanic", no_panic::no_panic)]
fn is_mark(c: char) -> bool {
    c == '-'
        || c == '_'
        || c == '.'
        || c == '!'
        || c == '~'
        || c == '*'
        || c == '\''
        || c == '('
        || c == ')'
}

#[cfg_attr(feature = "_nopanic", no_panic::no_panic)]
fn is_userinfo_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || is_mark(c)
        || c == '%'
        || c == ';'
        || c == ':'
        || c == '&'
        || c == '='
        || c == '+'
        || c == '$'
        || c == ','
}

#[cfg_attr(feature = "_nopanic", no_panic::no_panic)]
fn is_url_char(c: char) -> bool {
    !matches!(c, '\0'..='\u{001F}' | '#' | '?' | '\x7F')
}

#[cfg_attr(feature = "_nopanic", no_panic::no_panic)]
fn parse_url_start(ch: char) -> Result<State, ParseError> {
    // Proxied requests are followed by scheme of an absolute URI (alpha).
    // All methods except CONNECT are followed by '/' or '*'.
    if ch == '/' || ch == '*' {
        return Ok(State::Path);
    }

    if ch.is_ascii_alphabetic() {
        return Ok(State::Schema);
    }

    Err(ParseError::Invalid)
}

#[cfg_attr(feature = "_nopanic", no_panic::no_panic)]
fn parse_url_char(state: State, ch: char) -> Result<State, ParseError> {
    match state {
        State::Schema => {
            if ch.is_ascii_alphabetic() {
                return Ok(state);
            }

            if ch == ':' {
                return Ok(State::SchemaSlash);
            }
        }
        State::SchemaSlash => {
            if ch == '/' {
                return Ok(State::SchemaSlashSlash);
            }
        }
        State::SchemaSlashSlash => {
            if ch == '/' {
                return Ok(State::ServerStart);
            }
        }
        State::ServerWithAt | State::ServerStart | State::Server => {
            if state == State::ServerWithAt && ch == '@' {
                return Err(ParseError::Invalid);
            }

            if ch == '/' {
                return Ok(State::Path);
            }

            if ch == '?' {
                return Ok(State::QueryStringStart);
            }

            if ch == '@' {
                return Ok(State::ServerWithAt);
            }

            if is_userinfo_char(ch) || ch == '[' || ch == ']' {
                return Ok(State::Server);
            }
        }
        State::Path => {
            if is_url_char(ch) {
                return Ok(state);
            }

            if ch == '?' {
                return Ok(State::QueryStringStart);
            }

            if ch == '#' {
                return Ok(State::FragmentStart);
            }
        }
        State::QueryStringStart | State::QueryString => {
            if is_url_char(ch) {
                return Ok(State::QueryString);
            }

            if ch == '?' {
                // allow extra '?' in query string
                return Ok(State::QueryString);
            }

            if ch == '#' {
                return Ok(State::FragmentStart);
            }
        }
        State::FragmentStart => {
            if is_url_char(ch) {
                return Ok(State::Fragment);
            }
        }
        State::Fragment => {
            if is_url_char(ch) {
                return Ok(state);
            }
        }
    };

    // We should never fall out of the switch above unless there's an error
    Err(ParseError::Invalid)
}

#[derive(Debug, PartialEq, Eq)]
enum HttpHostState {
    UserinfoStart,
    Userinfo,
    HostStart,
    Hostv6Start,
    Host,
    Hostv6,
    Hostv6End,
    Hostv6ZoneStart,
    Hostv6Zone,
    HostPortStart,
    HostPort,
}

#[cfg_attr(feature = "_nopanic", no_panic::no_panic)]
fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-'
}

#[cfg_attr(feature = "_nopanic", no_panic::no_panic)]
fn parse_host_char(
    s: &HttpHostState,
    ch: char,
) -> Result<HttpHostState, ParseError> {
    match s {
        HttpHostState::Userinfo | HttpHostState::UserinfoStart => {
            if ch == '@' {
                return Ok(HttpHostState::HostStart);
            }

            if is_userinfo_char(ch) {
                return Ok(HttpHostState::Userinfo);
            }
        }
        HttpHostState::HostStart => {
            if ch == '[' {
                return Ok(HttpHostState::Hostv6Start);
            }

            if is_host_char(ch) {
                return Ok(HttpHostState::Host);
            }
        }
        HttpHostState::Host => {
            if is_host_char(ch) {
                return Ok(HttpHostState::Host);
            }
            if ch == ':' {
                return Ok(HttpHostState::HostPortStart);
            }
        }
        HttpHostState::Hostv6End => {
            if ch == ':' {
                return Ok(HttpHostState::HostPortStart);
            }
        }
        HttpHostState::Hostv6 | HttpHostState::Hostv6Start => {
            if s == &HttpHostState::Hostv6 && ch == ']' {
                return Ok(HttpHostState::Hostv6End);
            }

            if ch.is_ascii_hexdigit() || ch == ':' || ch == '.' {
                return Ok(HttpHostState::Hostv6);
            }

            if s == &HttpHostState::Hostv6 && ch == '%' {
                return Ok(HttpHostState::Hostv6ZoneStart);
            }
        }
        HttpHostState::Hostv6Zone | HttpHostState::Hostv6ZoneStart => {
            if s == &HttpHostState::Hostv6Zone && ch == ']' {
                return Ok(HttpHostState::Hostv6End);
            }

            // RFC 6874 Zone ID consists of 1*( unreserved / pct-encoded)
            if ch.is_ascii_alphanumeric()
                || ch == '%'
                || ch == '.'
                || ch == '-'
                || ch == '_'
                || ch == '~'
            {
                return Ok(HttpHostState::Hostv6Zone);
            }
        }
        HttpHostState::HostPort | HttpHostState::HostPortStart => {
            if ch.is_ascii_digit() {
                return Ok(HttpHostState::HostPort);
            }
        }
    }

    Err(ParseError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc_counter::{no_alloc, AllocCounterSystem};

    #[global_allocator]
    static A: AllocCounterSystem = AllocCounterSystem;

    #[test]
    #[no_alloc(forbid)]
    #[should_panic]
    /// Tests that the no_alloc attribute works
    fn test_no_alloc() {
        let _ = std::boxed::Box::new(8);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_request() {
        let result = Url::parse("http://hostname/").unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("hostname"),
            port: None,
            path: Some("/"),
            query: None,
            fragment: None,
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_request_with_port() {
        let result = Url::parse("http://hostname:444/").unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("hostname"),
            port: Some("444"),
            path: Some("/"),
            query: None,
            fragment: None,
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_connect_request() {
        let result = Url::parse_connect("hostname:443").unwrap();
        let expected = Url {
            schema: None,
            host: Some("hostname"),
            port: Some("443"),
            path: None,
            query: None,
            fragment: None,
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_ipv6_request() {
        let result = Url::parse("http://[1:2::3:4]/").unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("1:2::3:4"),
            port: None,
            path: Some("/"),
            query: None,
            fragment: None,
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_ipv6_request_with_port() {
        let result = Url::parse("http://[1:2::3:4]:67/").unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("1:2::3:4"),
            port: Some("67"),
            path: Some("/"),
            query: None,
            fragment: None,
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_connect_ipv6_address() {
        let result = Url::parse_connect("[1:2::3:4]:443").unwrap();
        let expected = Url {
            schema: None,
            host: Some("1:2::3:4"),
            port: Some("443"),
            path: None,
            query: None,
            fragment: None,
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_ipv4_in_ipv6_address() {
        let result =
            Url::parse("http://[2001:0000:0000:0000:0000:0000:1.9.1.1]/")
                .unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("2001:0000:0000:0000:0000:0000:1.9.1.1"),
            port: None,
            path: Some("/"),
            query: None,
            fragment: None,
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_extra_question_in_query_string() {
        let result = Url::parse(
            "http://a.tbcdn.cn/p/fp/2010c/??fp-header-min\
            .css,fp-base-min.css,fp-channel-min.css,fp-product-min.css,\
            fp-mall-min.css,fp-category-min.css,fp-sub-min.css,fp-gdp4p-min\
            .css,fp-css3-min.css,fp-misc-min.css?t=20101022.css",
        )
        .unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("a.tbcdn.cn"),
            port: None,
            path: Some("/p/fp/2010c/"),
            query: Some(
                "?fp-header-min.css,fp-base-min.css,fp-channel-min.css,\
            fp-product-min.css,fp-mall-min.css,fp-category-min.css,\
            fp-sub-min.css,fp-gdp4p-min.css,fp-css3-min.css,\
            fp-misc-min.css?t=20101022.css",
            ),
            fragment: None,
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_space_url_encoded() {
        let result = Url::parse("/toto.html?toto=a%20b").unwrap();
        let expected = Url {
            schema: None,
            host: None,
            port: None,
            path: Some("/toto.html"),
            query: Some("toto=a%20b"),
            fragment: None,
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_url_fragment() {
        let result = Url::parse("/toto.html#titi").unwrap();
        let expected = Url {
            schema: None,
            host: None,
            port: None,
            path: Some("/toto.html"),
            query: None,
            fragment: Some("titi"),
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_complex_url_fragment() {
        let result = Url::parse(
            "http://www.webmasterworld.com/r.cgi?f=21&d=8405\
            &url=http://www.example.com/index.html?foo=bar&hello=world#midpage",
        )
        .unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("www.webmasterworld.com"),
            port: None,
            path: Some("/r.cgi"),
            query: Some(
                "f=21&d=8405&url=http://www.example.com/index.html\
                 ?foo=bar&hello=world",
            ),
            fragment: Some("midpage"),
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_complex_url_from_node_js_url_parser_doc() {
        let result =
            Url::parse("http://host.com:8080/p/a/t/h?query=string#hash")
                .unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("host.com"),
            port: Some("8080"),
            path: Some("/p/a/t/h"),
            query: Some("query=string"),
            fragment: Some("hash"),
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_complex_url_with_basic_auth_from_node_js_url_parser_doc() {
        let result =
            Url::parse("http://a:b@host.com:8080/p/a/t/h?query=string#hash")
                .unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("host.com"),
            port: Some("8080"),
            path: Some("/p/a/t/h"),
            query: Some("query=string"),
            fragment: Some("hash"),
            userinfo: Some("a:b"),
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_basic_auth_with_space_url_encoded() {
        let result = Url::parse("http://a%20:b@host.com/").unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("host.com"),
            port: None,
            path: Some("/"),
            query: None,
            fragment: None,
            userinfo: Some("a%20:b"),
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_basic_auth_with_double_colon() {
        let result = Url::parse("http://a::b@host.com/").unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("host.com"),
            port: None,
            path: Some("/"),
            query: None,
            fragment: None,
            userinfo: Some("a::b"),
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_empty_basic_auth() {
        let result = Url::parse("http://@hostname/fo").unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("hostname"),
            port: None,
            path: Some("/fo"),
            query: None,
            fragment: None,
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_basic_auth_with_unreservedchars() {
        let result = Url::parse("http://a!;-_!=+$@host.com/").unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("host.com"),
            port: None,
            path: Some("/"),
            query: None,
            fragment: None,
            userinfo: Some("a!;-_!=+$"),
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_ipv6_address_with_zone_id() {
        let result = Url::parse("http://[fe80::a%25eth0]/").unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("fe80::a%25eth0"),
            port: None,
            path: Some("/"),
            query: None,
            fragment: None,
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_ipv6_address_with_zone_id_but_percent_is_not_percent_encoded() {
        let result = Url::parse("http://[fe80::a%eth0]/").unwrap();
        let expected = Url {
            schema: Some("http"),
            host: Some("fe80::a%eth0"),
            port: None,
            path: Some("/"),
            query: None,
            fragment: None,
            userinfo: None,
        };
        assert_eq!(expected, result);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_double_at() {
        let error = Url::parse("http://a:b@@hostname:443/").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_empty_host() {
        let error = Url::parse("http://:443/").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_empty_port() {
        let error = Url::parse("http://hostname:/").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_connect_with_basic_auth() {
        let error = Url::parse_connect("a:b@hostname:443").unwrap_err();
        assert_eq!(error, ParseError::InvalidConnect);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_connect_empty_host() {
        let error = Url::parse_connect(":443").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_connect_empty_port() {
        let error = Url::parse_connect("hostname:").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_connect_with_extra_bits() {
        let error = Url::parse_connect("hostname:443/").unwrap_err();
        assert_eq!(error, ParseError::InvalidConnect);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_space_in_url() {
        let error = Url::parse("/foo bar/").unwrap_err();
        assert_eq!(error, ParseError::Whitespace);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_carriage_return_in_url() {
        let error = Url::parse("/foo\rbar/").unwrap_err();
        assert_eq!(error, ParseError::Whitespace);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_double_colon_in_url() {
        let error = Url::parse("http://hostname::443/").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_line_feed_in_url() {
        let error = Url::parse("/foo\nbar/").unwrap_err();
        assert_eq!(error, ParseError::Whitespace);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_line_feed_in_hostname() {
        let error = Url::parse("http://host\name/fo").unwrap_err();
        assert_eq!(error, ParseError::Whitespace);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_percentage_in_hostname() {
        let error = Url::parse("http://host%name/fo").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_semicolon_in_hostname() {
        let error = Url::parse("http://host;ame/fo").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_only_empty_basic_auth() {
        let error = Url::parse("http://@/fo").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_only_basic_auth() {
        let error = Url::parse("http://toto@/fo").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_emtpy_hostname() {
        let error = Url::parse("http:///fo").unwrap_err();
        assert_eq!(error, ParseError::NoHost);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_proxy_equal_in_url() {
        let error = Url::parse("http://host=ame/fo").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_ipv6_address_ending_with() {
        let error = Url::parse("http://[fe80::a%]/").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_ipv6_address_with_zone_id_including_bad_character() {
        let error = Url::parse("http://[fe80::a%$HOME]/").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_just_ipv6_zone_id() {
        let error = Url::parse("http://[%eth0]/").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_empty_url() {
        let error = Url::parse("").unwrap_err();
        assert_eq!(error, ParseError::EmptyInput);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_full_of_spaces_url() {
        let error = Url::parse("  ").unwrap_err();
        assert_eq!(error, ParseError::Whitespace);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_tab_in_url() {
        let error = Url::parse("/foo	bar/").unwrap_err();
        assert_eq!(error, ParseError::Whitespace);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_form_feed_in_url() {
        let error = Url::parse("/foo\x0cbar/").unwrap_err();
        assert_eq!(error, ParseError::Whitespace);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_char_boundary_path_1() {
        let error = Url::parse("http://www.example.com/你好你好").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
        let error =
            Url::parse("http://www.example.com/?q=你好#foo").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
        let error = Url::parse("http://www.example.com/ＦＯＯ/?foo=%A1%C1")
            .unwrap_err();
        assert_eq!(error, ParseError::Invalid);
        let error = Url::parse("http://www.example.com/ＦＯＯ/?foo=%A1%C1")
            .unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_query_after_at() {
        let error = Url::parse("http://a:b@?foo").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_invalid_fragment() {
        let error = Url::parse("http://hostname#你").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_invalid_start() {
        let error = Url::parse("#").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }

    #[test]
    #[no_alloc(forbid)]
    fn test_invalid_userinfo_char() {
        let error = Url::parse("http://a}b@hostname").unwrap_err();
        assert_eq!(error, ParseError::Invalid);
    }
}
