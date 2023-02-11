use url_lite::Url;

fn main() {
    let input = "https://usr:pass@example.com:8080/some%20path?foo=bar#zzz";
    let url = Url::parse(input).expect("Invalid URL");

    println!("{url:#?}");

    assert_eq!(url.schema, Some("https"));
    assert_eq!(url.host, Some("example.com"));
    assert_eq!(url.port, Some("8080"));
    assert_eq!(url.path, Some("/some%20path"));
    assert_eq!(url.query, Some("foo=bar"));
    assert_eq!(url.fragment, Some("zzz"));
    assert_eq!(url.userinfo, Some("usr:pass"));
}
