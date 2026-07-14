#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalOpenPlatform {
    Linux,
    MacOs,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoopbackTarget {
    Localhost,
    Ipv4(std::net::Ipv4Addr),
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForwardingPreparationError {
    TooManyRequests,
    BindExhausted,
    CommandRejected,
    CommandTimedOut,
    AtomicCreationFailed,
    Unavailable,
}

pub(crate) trait ForwardingPreparation: Send {
    fn poll(&mut self) -> Option<Result<std::num::NonZeroU16, ForwardingPreparationError>>;

    fn cancel(&mut self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForwardingPolicySettlement {
    pub(crate) requested: bool,
    pub(crate) effective: bool,
    pub(crate) result: Result<(), ForwardingPreparationError>,
}

pub(crate) trait ForwardingPolicyChange: Send {
    fn poll(&mut self) -> Option<ForwardingPolicySettlement>;

    fn cancel(&mut self);
}

pub(crate) trait ForwardingController: Send + Sync {
    fn begin_prepare_numeric(
        &self,
        target: LoopbackTarget,
        remote_port: std::num::NonZeroU16,
    ) -> Result<Box<dyn ForwardingPreparation>, ForwardingPreparationError>;

    fn begin_set_enabled(
        &self,
        enabled: bool,
    ) -> Result<Box<dyn ForwardingPolicyChange>, ForwardingPreparationError>;
}

pub(crate) enum ExternalOpenForwarding {
    ManagedSshRequired,
    Unavailable,
    Available(std::sync::Arc<dyn ForwardingController>),
}

impl ExternalOpenForwarding {
    pub(crate) fn available(controller: std::sync::Arc<dyn ForwardingController>) -> Self {
        Self::Available(controller)
    }

    pub(crate) fn begin_prepare_numeric(
        &self,
        target: LoopbackTarget,
        remote_port: std::num::NonZeroU16,
    ) -> Result<Box<dyn ForwardingPreparation>, crate::protocol::ExternalOpenPreparationFailure>
    {
        match self {
            Self::ManagedSshRequired => {
                Err(crate::protocol::ExternalOpenPreparationFailure::ManagedSshRequired)
            }
            Self::Unavailable => {
                Err(crate::protocol::ExternalOpenPreparationFailure::ForwardingUnavailable)
            }
            Self::Available(controller) => controller
                .begin_prepare_numeric(target, remote_port)
                .map_err(crate::protocol::ExternalOpenPreparationFailure::from),
        }
    }

    pub(crate) fn begin_set_enabled(
        &self,
        enabled: bool,
    ) -> Result<Option<Box<dyn ForwardingPolicyChange>>, ForwardingPreparationError> {
        match self {
            Self::Available(controller) => controller.begin_set_enabled(enabled).map(Some),
            Self::ManagedSshRequired | Self::Unavailable => Ok(None),
        }
    }
}

impl From<ForwardingPreparationError> for crate::protocol::ExternalOpenPreparationFailure {
    fn from(error: ForwardingPreparationError) -> Self {
        match error {
            ForwardingPreparationError::TooManyRequests => Self::TooManyForwardRequests,
            ForwardingPreparationError::BindExhausted => Self::ForwardBindExhausted,
            ForwardingPreparationError::CommandRejected => Self::ForwardCommandRejected,
            ForwardingPreparationError::CommandTimedOut => Self::ForwardCommandTimedOut,
            ForwardingPreparationError::AtomicCreationFailed => Self::AtomicForwardCreationFailed,
            ForwardingPreparationError::Unavailable => Self::ForwardingUnavailable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedLoopbackUrl<'a> {
    original_url: &'a str,
    original_host: &'a str,
    target: LoopbackTarget,
    remote_port: std::num::NonZeroU16,
    rewrite_prefix: &'a str,
    rewrite_suffix: &'a str,
}

impl<'a> ValidatedLoopbackUrl<'a> {
    pub(crate) const fn original_url(&self) -> &'a str {
        self.original_url
    }

    pub(crate) const fn original_host(&self) -> &'a str {
        self.original_host
    }

    pub(crate) const fn target(&self) -> LoopbackTarget {
        self.target
    }

    pub(crate) const fn remote_port(&self) -> std::num::NonZeroU16 {
        self.remote_port
    }

    pub(crate) fn rewrite_with_local_port(&self, local_port: std::num::NonZeroU16) -> String {
        let port = local_port.to_string();
        let mut rewritten = String::with_capacity(
            self.rewrite_prefix.len() + 1 + port.len() + self.rewrite_suffix.len(),
        );
        rewritten.push_str(self.rewrite_prefix);
        rewritten.push(':');
        rewritten.push_str(&port);
        rewritten.push_str(self.rewrite_suffix);
        rewritten
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValidatedExternalOpenUrl<'a> {
    Ordinary(&'a str),
    Loopback(ValidatedLoopbackUrl<'a>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalOpenUrlError {
    UnsupportedScheme,
    AuthorityUserinfoForbidden,
    InvalidPort,
    InvalidAbsoluteUrl,
    UnsupportedLoopbackForm,
    LoopbackUnsupportedOnPlatform,
}

#[derive(Debug, Clone, Copy)]
enum HttpScheme {
    Http,
    Https,
}

impl HttpScheme {
    const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RawAuthority<'a> {
    value: &'a str,
    start: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRawAuthority<'a> {
    host: &'a str,
    explicit_port: Option<std::num::NonZeroU16>,
    port_range: std::ops::Range<usize>,
}

impl<'a> RawAuthority<'a> {
    fn parse(self) -> Result<ParsedRawAuthority<'a>, ExternalOpenUrlError> {
        let authority_end = self.start + self.value.len();
        if let Some(bracketed) = self.value.strip_prefix('[') {
            let Some(host_end) = bracketed.find(']') else {
                return Err(ExternalOpenUrlError::InvalidAbsoluteUrl);
            };
            let Some(host) = bracketed.get(..host_end) else {
                return Err(ExternalOpenUrlError::InvalidAbsoluteUrl);
            };
            let Some(remainder) = bracketed.get(host_end + 1..) else {
                return Err(ExternalOpenUrlError::InvalidAbsoluteUrl);
            };
            if remainder.is_empty() {
                return Ok(ParsedRawAuthority {
                    host,
                    explicit_port: None,
                    port_range: authority_end..authority_end,
                });
            }
            let Some(port) = remainder.strip_prefix(':') else {
                return Err(ExternalOpenUrlError::InvalidAbsoluteUrl);
            };
            return Ok(ParsedRawAuthority {
                host,
                explicit_port: Some(parse_port(port)?),
                port_range: (self.start + host_end + 2)..authority_end,
            });
        }

        let mut separators = self.value.match_indices(':');
        let first = separators.next();
        if separators.next().is_some() {
            return Ok(ParsedRawAuthority {
                host: self.value,
                explicit_port: None,
                port_range: authority_end..authority_end,
            });
        }
        let Some((separator, _)) = first else {
            return Ok(ParsedRawAuthority {
                host: self.value,
                explicit_port: None,
                port_range: authority_end..authority_end,
            });
        };
        let Some(host) = self.value.get(..separator) else {
            return Err(ExternalOpenUrlError::InvalidAbsoluteUrl);
        };
        let Some(port) = self.value.get(separator + 1..) else {
            return Err(ExternalOpenUrlError::InvalidPort);
        };
        Ok(ParsedRawAuthority {
            host,
            explicit_port: Some(parse_port(port)?),
            port_range: (self.start + separator)..authority_end,
        })
    }
}

pub(crate) fn validate_external_open_url(
    input: &str,
    platform: ExternalOpenPlatform,
) -> Result<ValidatedExternalOpenUrl<'_>, ExternalOpenUrlError> {
    let (scheme, scheme_end) = parse_http_scheme(input)?;
    let authority =
        raw_authority(input, scheme_end).ok_or(ExternalOpenUrlError::InvalidAbsoluteUrl)?;
    if authority.value.contains('@') {
        return Err(ExternalOpenUrlError::AuthorityUserinfoForbidden);
    }
    let parsed_authority = authority.parse()?;
    let original_host = parsed_authority.host;
    if original_host.is_empty()
        || input
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(ExternalOpenUrlError::InvalidAbsoluteUrl);
    }

    let parsed = url::Url::parse(input).map_err(|_| ExternalOpenUrlError::InvalidAbsoluteUrl)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.has_host()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(ExternalOpenUrlError::InvalidAbsoluteUrl);
    }

    let target = match parsed.host() {
        Some(url::Host::Domain(host)) => {
            if original_host.eq_ignore_ascii_case("localhost")
                && host.eq_ignore_ascii_case("localhost")
            {
                Some(LoopbackTarget::Localhost)
            } else if host.eq_ignore_ascii_case("localhost")
                || is_localhost_namespace_form(host)
                || is_localhost_namespace_form(original_host)
            {
                return Err(ExternalOpenUrlError::UnsupportedLoopbackForm);
            } else {
                None
            }
        }
        Some(url::Host::Ipv4(address)) => {
            let Some(source_address) = parse_canonical_ipv4(original_host) else {
                return Err(ExternalOpenUrlError::UnsupportedLoopbackForm);
            };
            if source_address != address {
                return Err(ExternalOpenUrlError::UnsupportedLoopbackForm);
            }
            (address.octets()[0] == 127).then_some(LoopbackTarget::Ipv4(address))
        }
        Some(url::Host::Ipv6(address)) => {
            if address.to_ipv4_mapped().is_some() {
                return Err(ExternalOpenUrlError::UnsupportedLoopbackForm);
            }
            if address == std::net::Ipv6Addr::LOCALHOST {
                if original_host == "::1" {
                    Some(LoopbackTarget::Ipv6)
                } else {
                    return Err(ExternalOpenUrlError::UnsupportedLoopbackForm);
                }
            } else {
                None
            }
        }
        None => return Err(ExternalOpenUrlError::InvalidAbsoluteUrl),
    };

    let Some(target) = target else {
        return Ok(ValidatedExternalOpenUrl::Ordinary(input));
    };
    match (platform, target) {
        (ExternalOpenPlatform::Linux, _)
        | (ExternalOpenPlatform::MacOs, LoopbackTarget::Localhost)
        | (ExternalOpenPlatform::MacOs, LoopbackTarget::Ipv6)
        | (ExternalOpenPlatform::MacOs, LoopbackTarget::Ipv4(std::net::Ipv4Addr::LOCALHOST)) => {}
        (ExternalOpenPlatform::MacOs | ExternalOpenPlatform::Unsupported, _) => {
            return Err(ExternalOpenUrlError::LoopbackUnsupportedOnPlatform);
        }
    }
    let remote_port = parsed_authority
        .explicit_port
        .or_else(|| std::num::NonZeroU16::new(scheme.default_port()))
        .ok_or(ExternalOpenUrlError::InvalidPort)?;
    let rewrite_prefix = input
        .get(..parsed_authority.port_range.start)
        .ok_or(ExternalOpenUrlError::InvalidAbsoluteUrl)?;
    let rewrite_suffix = input
        .get(parsed_authority.port_range.end..)
        .ok_or(ExternalOpenUrlError::InvalidAbsoluteUrl)?;

    Ok(ValidatedExternalOpenUrl::Loopback(ValidatedLoopbackUrl {
        original_url: input,
        original_host,
        target,
        remote_port,
        rewrite_prefix,
        rewrite_suffix,
    }))
}

fn parse_http_scheme(input: &str) -> Result<(HttpScheme, usize), ExternalOpenUrlError> {
    let Some(scheme_end) = input.find(':') else {
        return Err(ExternalOpenUrlError::UnsupportedScheme);
    };
    let Some(scheme) = input.get(..scheme_end) else {
        return Err(ExternalOpenUrlError::UnsupportedScheme);
    };
    if scheme.eq_ignore_ascii_case("http") {
        Ok((HttpScheme::Http, scheme_end))
    } else if scheme.eq_ignore_ascii_case("https") {
        Ok((HttpScheme::Https, scheme_end))
    } else {
        Err(ExternalOpenUrlError::UnsupportedScheme)
    }
}

fn raw_authority(input: &str, scheme_end: usize) -> Option<RawAuthority<'_>> {
    let authority = input.get(scheme_end + 1..)?.strip_prefix("//")?;
    let authority_end = authority
        .find(['/', '\\', '?', '#'])
        .unwrap_or(authority.len());
    Some(RawAuthority {
        value: authority.get(..authority_end)?,
        start: scheme_end + 3,
    })
}

fn parse_port(port: &str) -> Result<std::num::NonZeroU16, ExternalOpenUrlError> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ExternalOpenUrlError::InvalidPort);
    }
    let parsed = port
        .parse::<u16>()
        .map_err(|_| ExternalOpenUrlError::InvalidPort)?;
    std::num::NonZeroU16::new(parsed).ok_or(ExternalOpenUrlError::InvalidPort)
}

fn is_localhost_namespace_form(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    host.eq_ignore_ascii_case("localhost")
        || host
            .rsplit_once('.')
            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("localhost"))
}

fn parse_canonical_ipv4(host: &str) -> Option<std::net::Ipv4Addr> {
    let mut octets = [0_u8; 4];
    let mut parts = host.split('.');
    for octet in &mut octets {
        let part = parts.next()?;
        if part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(std::net::Ipv4Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_preparation_errors_have_one_exhaustive_external_failure_translation() {
        for (error, expected) in [
            (
                ForwardingPreparationError::TooManyRequests,
                crate::protocol::ExternalOpenPreparationFailure::TooManyForwardRequests,
            ),
            (
                ForwardingPreparationError::BindExhausted,
                crate::protocol::ExternalOpenPreparationFailure::ForwardBindExhausted,
            ),
            (
                ForwardingPreparationError::CommandRejected,
                crate::protocol::ExternalOpenPreparationFailure::ForwardCommandRejected,
            ),
            (
                ForwardingPreparationError::CommandTimedOut,
                crate::protocol::ExternalOpenPreparationFailure::ForwardCommandTimedOut,
            ),
            (
                ForwardingPreparationError::AtomicCreationFailed,
                crate::protocol::ExternalOpenPreparationFailure::AtomicForwardCreationFailed,
            ),
            (
                ForwardingPreparationError::Unavailable,
                crate::protocol::ExternalOpenPreparationFailure::ForwardingUnavailable,
            ),
        ] {
            assert_eq!(
                crate::protocol::ExternalOpenPreparationFailure::from(error),
                expected
            );
        }
    }

    #[test]
    fn ordinary_web_urls_preserve_input_bytes() {
        let cases = [
            "HTTPS://Example.COM/a%2Fb?token=A%2BB#Frag",
            "HTTPS://Example%2eCOM/a%2Fb?token=A%2BB#Frag",
            "http://example.test:00080/path@name?email=a@b#@fragment",
            "http://example.test\\path@name?email=a@b#@fragment",
            "https://localhost.example/path",
            "http://127.0.0.1.example/path",
            "http://192.0.2.1:65535/",
            "https://[2001:db8::1]/a;b?x=%2F#frag",
        ];

        for input in cases {
            assert_eq!(
                validate_external_open_url(input, ExternalOpenPlatform::Linux),
                Ok(ValidatedExternalOpenUrl::Ordinary(input)),
                "input: {input}"
            );
        }
    }

    #[test]
    fn localhost_namespace_variants_fail_closed_with_policy_precedence() {
        let cases = [
            (
                "ftp://user@.localhost:70000",
                ExternalOpenPlatform::MacOs,
                ExternalOpenUrlError::UnsupportedScheme,
            ),
            (
                "http://user@.localhost:70000",
                ExternalOpenPlatform::MacOs,
                ExternalOpenUrlError::AuthorityUserinfoForbidden,
            ),
            (
                "http://.localhost:70000",
                ExternalOpenPlatform::MacOs,
                ExternalOpenUrlError::InvalidPort,
            ),
            (
                "http://.localhost path",
                ExternalOpenPlatform::MacOs,
                ExternalOpenUrlError::InvalidAbsoluteUrl,
            ),
            (
                "http://.localhost",
                ExternalOpenPlatform::MacOs,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://.LOCALHOST",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://..localhost",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://dev..localhost",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://.localhost.",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://localhost..",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://%2elocalhost",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://dev%2elocalhost",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://localhost%2e",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://loc%61lhost",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://%6c%6f%63%61%6c%68%6f%73%74",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://。localhost",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://．localhost",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://｡localhost",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://dev。localhost",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://dev．localhost",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://dev｡localhost",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://localhost。",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://localhost．",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://localhost｡",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://localhost%E3%80%82",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://ｌｏｃａｌｈｏｓｔ",
                ExternalOpenPlatform::Linux,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
        ];

        for (input, platform, expected) in cases {
            assert_eq!(
                validate_external_open_url(input, platform),
                Err(expected),
                "input: {input}, platform: {platform:?}"
            );
        }
    }

    #[test]
    fn ambiguous_loopback_and_numeric_forms_fail_closed() {
        let cases = [
            "http://localhost.",
            "http://localhost%2e",
            "http://LOCALHOST%2E",
            "http://dev.localhost",
            "http://dev%2elocalhost",
            "http://dev%2ELOCALHOST",
            "http://dev.LOCALHOST.",
            "http://127.1",
            "http://127.0.1",
            "http://2130706433",
            "http://0x7f000001",
            "http://0177.0.0.1",
            "http://127.00.0.1",
            "http://127.0.0.1.",
            "http://192.168.1",
            "http://[0:0:0:0:0:0:0:1]",
            "http://[::ffff:127.0.0.1]",
            "http://[::ffff:c000:201]",
        ];

        for input in cases {
            assert_eq!(
                validate_external_open_url(input, ExternalOpenPlatform::Linux),
                Err(ExternalOpenUrlError::UnsupportedLoopbackForm),
                "input: {input}"
            );
        }
    }

    #[test]
    fn platform_restrictions_apply_only_to_recognized_loopback_targets() {
        let rejected = [
            (
                "http://127.0.0.2",
                ExternalOpenPlatform::MacOs,
                ExternalOpenUrlError::LoopbackUnsupportedOnPlatform,
            ),
            (
                "http://localhost",
                ExternalOpenPlatform::Unsupported,
                ExternalOpenUrlError::LoopbackUnsupportedOnPlatform,
            ),
            (
                "http://127.0.0.1",
                ExternalOpenPlatform::Unsupported,
                ExternalOpenUrlError::LoopbackUnsupportedOnPlatform,
            ),
            (
                "http://[::1]",
                ExternalOpenPlatform::Unsupported,
                ExternalOpenUrlError::LoopbackUnsupportedOnPlatform,
            ),
        ];
        for (input, platform, expected) in rejected {
            assert_eq!(
                validate_external_open_url(input, platform),
                Err(expected),
                "input: {input}, platform: {platform:?}"
            );
        }

        for input in ["http://localhost", "http://127.0.0.1", "http://[::1]"] {
            assert!(
                matches!(
                    validate_external_open_url(input, ExternalOpenPlatform::MacOs),
                    Ok(ValidatedExternalOpenUrl::Loopback(_))
                ),
                "input: {input}"
            );
        }
        assert_eq!(
            validate_external_open_url(
                "https://example.test/path",
                ExternalOpenPlatform::Unsupported,
            ),
            Ok(ValidatedExternalOpenUrl::Ordinary(
                "https://example.test/path"
            ))
        );
    }

    #[test]
    fn malformed_inputs_have_closed_typed_rejections() {
        let cases = [
            ("", ExternalOpenUrlError::UnsupportedScheme),
            ("/relative", ExternalOpenUrlError::UnsupportedScheme),
            ("//example.com", ExternalOpenUrlError::UnsupportedScheme),
            (
                "mailto:user@example.com",
                ExternalOpenUrlError::UnsupportedScheme,
            ),
            ("http:example.com", ExternalOpenUrlError::InvalidAbsoluteUrl),
            ("http:///path", ExternalOpenUrlError::InvalidAbsoluteUrl),
            (
                "http://user@example.com/path",
                ExternalOpenUrlError::AuthorityUserinfoForbidden,
            ),
            (
                "http://user:password@example.com/path",
                ExternalOpenUrlError::AuthorityUserinfoForbidden,
            ),
            (
                "http://@example.com/path",
                ExternalOpenUrlError::AuthorityUserinfoForbidden,
            ),
            (
                "http://:@example.com/path",
                ExternalOpenUrlError::AuthorityUserinfoForbidden,
            ),
            (
                "http://:password@example.com/path",
                ExternalOpenUrlError::AuthorityUserinfoForbidden,
            ),
            ("http://example.com:0", ExternalOpenUrlError::InvalidPort),
            (
                "http://example.com:65536",
                ExternalOpenUrlError::InvalidPort,
            ),
            ("http://example.com:", ExternalOpenUrlError::InvalidPort),
            (
                "http://example.com:not-a-port",
                ExternalOpenUrlError::InvalidPort,
            ),
            ("http://example.com:+80", ExternalOpenUrlError::InvalidPort),
            ("http://[::1]:70000/path", ExternalOpenUrlError::InvalidPort),
            (
                "http://example.com/path with space",
                ExternalOpenUrlError::InvalidAbsoluteUrl,
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(
                validate_external_open_url(input, ExternalOpenPlatform::Linux),
                Err(expected),
                "input: {input}"
            );
        }
    }

    #[test]
    fn loopback_rewrite_changes_only_the_explicit_local_port() {
        let cases = [
            (
                "HTTPS://LOCALHOST:00443/a%2Fb?token=A%2BB#Frag",
                43_123,
                "HTTPS://LOCALHOST:43123/a%2Fb?token=A%2BB#Frag",
            ),
            (
                "http://127.0.0.42/path;value?empty=&at=a@b#section-2",
                8_080,
                "http://127.0.0.42:8080/path;value?empty=&at=a@b#section-2",
            ),
            (
                "https://[::1]?capability=%2Fsecret#result",
                9443,
                "https://[::1]:9443?capability=%2Fsecret#result",
            ),
            (
                "http://LOCALHOST\\path@name?token=A%2BB#Frag",
                8080,
                "http://LOCALHOST:8080\\path@name?token=A%2BB#Frag",
            ),
            ("http://localhost#", 80, "http://localhost:80#"),
        ];

        for (input, local_port, expected) in cases {
            let validated = validate_external_open_url(input, ExternalOpenPlatform::Linux)
                .expect("test URL should be eligible loopback");
            let ValidatedExternalOpenUrl::Loopback(loopback) = validated else {
                panic!("test URL should require forwarding: {input}");
            };
            let local_port =
                std::num::NonZeroU16::new(local_port).expect("test local port should be nonzero");

            assert_eq!(
                loopback.rewrite_with_local_port(local_port),
                expected,
                "input: {input}"
            );
        }
    }

    #[test]
    fn rejection_precedence_is_deterministic() {
        let cases = [
            (
                "ftp://user@example.com:70000",
                ExternalOpenPlatform::MacOs,
                ExternalOpenUrlError::UnsupportedScheme,
            ),
            (
                "http://user@127.1:70000",
                ExternalOpenPlatform::MacOs,
                ExternalOpenUrlError::AuthorityUserinfoForbidden,
            ),
            (
                "http://127.0.0.2:70000",
                ExternalOpenPlatform::MacOs,
                ExternalOpenUrlError::InvalidPort,
            ),
            (
                "http://[0:0:0:0:0:0:0:1",
                ExternalOpenPlatform::MacOs,
                ExternalOpenUrlError::InvalidAbsoluteUrl,
            ),
            (
                "http://127.1",
                ExternalOpenPlatform::MacOs,
                ExternalOpenUrlError::UnsupportedLoopbackForm,
            ),
            (
                "http://127.0.0.2",
                ExternalOpenPlatform::MacOs,
                ExternalOpenUrlError::LoopbackUnsupportedOnPlatform,
            ),
        ];

        for (input, platform, expected) in cases {
            assert_eq!(
                validate_external_open_url(input, platform),
                Err(expected),
                "input: {input}"
            );
        }
    }

    #[test]
    fn linux_recognizes_only_canonical_loopback_targets_with_effective_ports() {
        let cases = [
            (
                "http://localhost",
                LoopbackTarget::Localhost,
                "localhost",
                80,
            ),
            (
                "https://LOCALHOST/path",
                LoopbackTarget::Localhost,
                "LOCALHOST",
                443,
            ),
            (
                "http://127.0.0.0",
                LoopbackTarget::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 0)),
                "127.0.0.0",
                80,
            ),
            (
                "http://127.0.0.1:1",
                LoopbackTarget::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                "127.0.0.1",
                1,
            ),
            (
                "https://127.255.255.255:65535",
                LoopbackTarget::Ipv4(std::net::Ipv4Addr::new(127, 255, 255, 255)),
                "127.255.255.255",
                65_535,
            ),
            ("https://[::1]", LoopbackTarget::Ipv6, "::1", 443),
            ("http://[::1]:3000", LoopbackTarget::Ipv6, "::1", 3000),
        ];

        for (input, expected_target, expected_host, expected_port) in cases {
            let result =
                validate_external_open_url(input, ExternalOpenPlatform::Linux).map(|validated| {
                    match validated {
                        ValidatedExternalOpenUrl::Ordinary(_) => None,
                        ValidatedExternalOpenUrl::Loopback(loopback) => Some((
                            loopback.original_url(),
                            loopback.target(),
                            loopback.original_host(),
                            loopback.remote_port().get(),
                        )),
                    }
                });

            assert_eq!(
                result,
                Ok(Some((input, expected_target, expected_host, expected_port))),
                "input: {input}"
            );
        }
    }
}
