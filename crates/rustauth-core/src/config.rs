//! `AuthConfig`: settings for the services, built by hand with [`AuthConfig::builder`] or parsed
//! from the `AUTH_*` variables with [`AuthConfig::parse`].

use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::str::FromStr;

use chrono::TimeDelta;

use crate::values::IpRange;

const REGISTRATION_OPEN: &str = "AUTH_REGISTRATION_OPEN";
const SETUP_TOKEN: &str = "AUTH_SETUP_TOKEN";
const SESSION_TTL_DAYS: &str = "AUTH_SESSION_TTL_DAYS";
const SESSION_MAX_DAYS: &str = "AUTH_SESSION_MAX_DAYS";
const TRUSTED_PROXIES: &str = "AUTH_TRUSTED_PROXIES";
const LOCKOUT_THRESHOLD: &str = "AUTH_LOCKOUT_THRESHOLD";
const LOCKOUT_MINUTES: &str = "AUTH_LOCKOUT_MINUTES";
const LOCKOUT_MAX_MINUTES: &str = "AUTH_LOCKOUT_MAX_MINUTES";
const IP_FAILURE_LIMIT: &str = "AUTH_IP_FAILURE_LIMIT";
const RATE_LIMIT_PER_MINUTE: &str = "AUTH_RATE_LIMIT_PER_MINUTE";
/// Builder-only settings have no variable; errors name the builder method instead.
const FAILURE_WINDOW: &str = "failure_window";
const TOUCH_INTERVAL: &str = "touch_interval";
/// The order errors list fields in: the variables as documented, then builder-only settings.
const ORDER: [&str; 12] = [
    REGISTRATION_OPEN,
    SETUP_TOKEN,
    SESSION_TTL_DAYS,
    SESSION_MAX_DAYS,
    TRUSTED_PROXIES,
    LOCKOUT_THRESHOLD,
    LOCKOUT_MINUTES,
    LOCKOUT_MAX_MINUTES,
    IP_FAILURE_LIMIT,
    RATE_LIMIT_PER_MINUTE,
    FAILURE_WINDOW,
    TOUCH_INTERVAL,
];

/// Longest session lifetimes accepted (about ten years), which keeps date arithmetic in range.
const MAX_SESSION_DAYS: u32 = 3650;
/// Longest lockout and window accepted (one year).
const MAX_LOCKOUT_MINUTES: u32 = 525_600;
/// Setup tokens shorter than this are too easy to guess.
const MIN_SETUP_TOKEN_CHARS: usize = 16;

/// Invalid configuration: names every offending variable (or builder setting) at once.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("rustauth.config.invalid {}", fields.join(", "))]
pub struct ConfigError {
    pub fields: Vec<&'static str>,
}

/// Settings for the auth services. Defaults match the design; see the table under
/// "Configuration" in `docs/design/rustauth.md`.
#[derive(Clone)]
pub struct AuthConfig {
    registration_open: bool,
    setup_token: Option<String>,
    session_ttl: TimeDelta,
    session_max: TimeDelta,
    trusted_proxies: Vec<IpRange>,
    lockout_threshold: u32,
    lockout_duration: TimeDelta,
    lockout_max: TimeDelta,
    failure_window: TimeDelta,
    ip_failure_limit: u32,
    rate_limit_per_minute: u32,
    touch_interval: TimeDelta,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            registration_open: false,
            setup_token: None,
            session_ttl: TimeDelta::days(30),
            session_max: TimeDelta::days(90),
            trusted_proxies: Vec::new(),
            lockout_threshold: 5,
            lockout_duration: TimeDelta::minutes(15),
            lockout_max: TimeDelta::minutes(1440),
            failure_window: TimeDelta::minutes(15),
            ip_failure_limit: 30,
            rate_limit_per_minute: 60,
            touch_interval: TimeDelta::hours(1),
        }
    }
}

impl AuthConfig {
    /// Starts from the defaults.
    pub fn builder() -> AuthConfigBuilder {
        AuthConfigBuilder {
            config: Self::default(),
        }
    }

    /// Reads the `AUTH_*` variables from a name to value map (for example
    /// `std::env::vars().collect()`). Blank values count as unset. Every invalid variable is
    /// reported in one [`ConfigError`].
    pub fn parse<K, V, S>(env: &HashMap<K, V, S>) -> Result<Self, ConfigError>
    where
        K: Borrow<str> + Eq + Hash,
        V: AsRef<str>,
        S: BuildHasher,
    {
        let mut reader = Reader {
            lookup: &|name: &str| env.get(name).map(AsRef::as_ref),
            invalid: Vec::new(),
        };
        let defaults = Self::default();
        let registration_open = reader.flag(REGISTRATION_OPEN, defaults.registration_open);
        let setup_token = reader.text(SETUP_TOKEN);
        let session_ttl = reader.number(SESSION_TTL_DAYS, 30, MAX_SESSION_DAYS);
        let session_max = reader.number(SESSION_MAX_DAYS, 90, MAX_SESSION_DAYS);
        let trusted_proxies = reader.list::<IpRange>(TRUSTED_PROXIES);
        let lockout_threshold = reader.number(LOCKOUT_THRESHOLD, 5, u32::MAX);
        let lockout_minutes = reader.number(LOCKOUT_MINUTES, 15, MAX_LOCKOUT_MINUTES);
        let lockout_max_minutes = reader.number(LOCKOUT_MAX_MINUTES, 1440, MAX_LOCKOUT_MINUTES);
        let ip_failure_limit = reader.number(IP_FAILURE_LIMIT, 30, u32::MAX);
        let rate_limit_per_minute = reader.number(RATE_LIMIT_PER_MINUTE, 60, u32::MAX);

        let mut builder = Self::builder()
            .registration_open(registration_open)
            .session_ttl(TimeDelta::days(session_ttl.into()))
            .session_max(TimeDelta::days(session_max.into()))
            .trusted_proxies(trusted_proxies)
            .lockout_threshold(lockout_threshold)
            .lockout_duration(TimeDelta::minutes(lockout_minutes.into()))
            .lockout_max(TimeDelta::minutes(lockout_max_minutes.into()))
            .ip_failure_limit(ip_failure_limit)
            .rate_limit_per_minute(rate_limit_per_minute);
        if let Some(token) = setup_token {
            builder = builder.setup_token(token);
        }
        let mut fields = reader.invalid;
        match builder.build() {
            Ok(config) if fields.is_empty() => Ok(config),
            Ok(_) => Err(ConfigError { fields }),
            Err(error) => {
                for field in error.fields {
                    if !fields.contains(&field) {
                        fields.push(field);
                    }
                }
                fields.sort_by_key(|field| ORDER.iter().position(|name| name == field));
                Err(ConfigError { fields })
            }
        }
    }

    /// Whether anyone may sign up after the first (administrator) account. Default `false`.
    pub fn registration_open(&self) -> bool {
        self.registration_open
    }

    /// The token the first registration must present. When `None`, the service generates one
    /// at startup and logs it once (`rustauth.setup.token-issued`).
    pub fn setup_token(&self) -> Option<&str> {
        self.setup_token.as_deref()
    }

    /// Sliding session lifetime. Default 30 days.
    pub fn session_ttl(&self) -> TimeDelta {
        self.session_ttl
    }

    /// Absolute session lifetime from creation. Default 90 days.
    pub fn session_max(&self) -> TimeDelta {
        self.session_max
    }

    /// Peers whose `X-Forwarded-For` header is trusted. Default empty.
    pub fn trusted_proxies(&self) -> &[IpRange] {
        &self.trusted_proxies
    }

    /// Wrong passwords in a row (within the failure window) before the account locks. Default 5.
    pub fn lockout_threshold(&self) -> u32 {
        self.lockout_threshold
    }

    /// First lockout length; each consecutive lockout doubles it. Default 15 minutes.
    pub fn lockout_duration(&self) -> TimeDelta {
        self.lockout_duration
    }

    /// Longest lockout. Default 24 hours.
    pub fn lockout_max(&self) -> TimeDelta {
        self.lockout_max
    }

    /// Failures older than this start a new count, for accounts and per client IP. Default 15
    /// minutes.
    pub fn failure_window(&self) -> TimeDelta {
        self.failure_window
    }

    /// Failed sign-ins per client IP per failure window. Default 30.
    pub fn ip_failure_limit(&self) -> u32 {
        self.ip_failure_limit
    }

    /// Requests per client IP per minute to the public auth routes. Default 60.
    pub fn rate_limit_per_minute(&self) -> u32 {
        self.rate_limit_per_minute
    }

    /// How often a used session writes `last_used_at` and slides its expiry. Default 1 hour.
    pub fn touch_interval(&self) -> TimeDelta {
        self.touch_interval
    }
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthConfig")
            .field("registration_open", &self.registration_open)
            .field("setup_token", &self.setup_token.as_ref().map(|_| "***"))
            .field("session_ttl", &self.session_ttl)
            .field("session_max", &self.session_max)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("lockout_threshold", &self.lockout_threshold)
            .field("lockout_duration", &self.lockout_duration)
            .field("lockout_max", &self.lockout_max)
            .field("failure_window", &self.failure_window)
            .field("ip_failure_limit", &self.ip_failure_limit)
            .field("rate_limit_per_minute", &self.rate_limit_per_minute)
            .field("touch_interval", &self.touch_interval)
            .finish()
    }
}

/// Builds an [`AuthConfig`] from the defaults. [`AuthConfigBuilder::build`] validates the
/// result; its errors name the matching `AUTH_*` variable, or the builder method for settings
/// without one.
#[derive(Clone, Debug)]
pub struct AuthConfigBuilder {
    config: AuthConfig,
}

impl AuthConfigBuilder {
    pub fn registration_open(mut self, open: bool) -> Self {
        self.config.registration_open = open;
        self
    }

    /// At least 16 characters.
    pub fn setup_token(mut self, token: impl Into<String>) -> Self {
        self.config.setup_token = Some(token.into());
        self
    }

    pub fn session_ttl(mut self, ttl: TimeDelta) -> Self {
        self.config.session_ttl = ttl;
        self
    }

    /// At least the sliding lifetime.
    pub fn session_max(mut self, max: TimeDelta) -> Self {
        self.config.session_max = max;
        self
    }

    pub fn trusted_proxies(mut self, proxies: Vec<IpRange>) -> Self {
        self.config.trusted_proxies = proxies;
        self
    }

    pub fn lockout_threshold(mut self, threshold: u32) -> Self {
        self.config.lockout_threshold = threshold;
        self
    }

    pub fn lockout_duration(mut self, duration: TimeDelta) -> Self {
        self.config.lockout_duration = duration;
        self
    }

    /// At least the first lockout length.
    pub fn lockout_max(mut self, max: TimeDelta) -> Self {
        self.config.lockout_max = max;
        self
    }

    pub fn failure_window(mut self, window: TimeDelta) -> Self {
        self.config.failure_window = window;
        self
    }

    pub fn ip_failure_limit(mut self, limit: u32) -> Self {
        self.config.ip_failure_limit = limit;
        self
    }

    pub fn rate_limit_per_minute(mut self, limit: u32) -> Self {
        self.config.rate_limit_per_minute = limit;
        self
    }

    pub fn touch_interval(mut self, interval: TimeDelta) -> Self {
        self.config.touch_interval = interval;
        self
    }

    pub fn build(self) -> Result<AuthConfig, ConfigError> {
        let config = self.config;
        let sessions = TimeDelta::days(MAX_SESSION_DAYS.into());
        let lockouts = TimeDelta::minutes(MAX_LOCKOUT_MINUTES.into());
        let within = |value: TimeDelta, max: TimeDelta| value > TimeDelta::zero() && value <= max;
        let checks = [
            (
                SETUP_TOKEN,
                config.setup_token.as_ref().is_none_or(|token| {
                    token.chars().count() >= MIN_SETUP_TOKEN_CHARS
                        && !token.chars().any(char::is_whitespace)
                }),
            ),
            (SESSION_TTL_DAYS, within(config.session_ttl, sessions)),
            (
                SESSION_MAX_DAYS,
                within(config.session_max, sessions) && config.session_max >= config.session_ttl,
            ),
            (LOCKOUT_THRESHOLD, config.lockout_threshold >= 1),
            (LOCKOUT_MINUTES, within(config.lockout_duration, lockouts)),
            (
                LOCKOUT_MAX_MINUTES,
                within(config.lockout_max, lockouts)
                    && config.lockout_max >= config.lockout_duration,
            ),
            (IP_FAILURE_LIMIT, config.ip_failure_limit >= 1),
            (RATE_LIMIT_PER_MINUTE, config.rate_limit_per_minute >= 1),
            (FAILURE_WINDOW, within(config.failure_window, lockouts)),
            (TOUCH_INTERVAL, within(config.touch_interval, sessions)),
        ];
        let fields: Vec<&'static str> = checks
            .into_iter()
            .filter(|(_, ok)| !ok)
            .map(|(field, _)| field)
            .collect();
        if fields.is_empty() {
            Ok(config)
        } else {
            Err(ConfigError { fields })
        }
    }
}

/// Reads variables and collects the names of invalid ones.
struct Reader<'a> {
    lookup: &'a dyn Fn(&str) -> Option<&'a str>,
    invalid: Vec<&'static str>,
}

impl Reader<'_> {
    fn get(&self, name: &str) -> Option<&str> {
        (self.lookup)(name)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn reject(&mut self, name: &'static str) {
        if !self.invalid.contains(&name) {
            self.invalid.push(name);
        }
    }

    fn text(&mut self, name: &'static str) -> Option<String> {
        self.get(name).map(str::to_owned)
    }

    /// `true` or `false`, in any letter case.
    fn flag(&mut self, name: &'static str, default: bool) -> bool {
        match self.get(name).map(str::to_ascii_lowercase).as_deref() {
            None => default,
            Some("true") => true,
            Some("false") => false,
            Some(_) => {
                self.reject(name);
                default
            }
        }
    }

    /// A whole number from 1 to `max`.
    fn number(&mut self, name: &'static str, default: u32, max: u32) -> u32 {
        match self.get(name).map(str::parse::<u32>) {
            None => default,
            Some(Ok(value)) if (1..=max).contains(&value) => value,
            Some(_) => {
                self.reject(name);
                default
            }
        }
    }

    /// Comma-separated values; empty entries are skipped.
    fn list<T: FromStr>(&mut self, name: &'static str) -> Vec<T> {
        let Some(value) = self.get(name) else {
            return Vec::new();
        };
        let parsed: Result<Vec<T>, _> = value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::parse)
            .collect();
        parsed.unwrap_or_else(|_| {
            self.reject(name);
            Vec::new()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn fields(pairs: &[(&str, &str)]) -> Vec<&'static str> {
        AuthConfig::parse(&env(pairs)).expect_err("invalid").fields
    }

    #[test]
    fn applies_the_defaults() {
        let config = AuthConfig::parse(&env(&[])).expect("valid");
        assert!(!config.registration_open());
        assert_eq!(config.setup_token(), None);
        assert_eq!(config.session_ttl(), TimeDelta::days(30));
        assert_eq!(config.session_max(), TimeDelta::days(90));
        assert!(config.trusted_proxies().is_empty());
        assert_eq!(config.lockout_threshold(), 5);
        assert_eq!(config.lockout_duration(), TimeDelta::minutes(15));
        assert_eq!(config.lockout_max(), TimeDelta::hours(24));
        assert_eq!(config.failure_window(), TimeDelta::minutes(15));
        assert_eq!(config.ip_failure_limit(), 30);
        assert_eq!(config.rate_limit_per_minute(), 60);
        assert_eq!(config.touch_interval(), TimeDelta::hours(1));
    }

    #[test]
    fn reads_every_variable() {
        let config = AuthConfig::parse(&env(&[
            ("AUTH_REGISTRATION_OPEN", "TRUE"),
            ("AUTH_SETUP_TOKEN", "a-long-enough-setup-token"),
            ("AUTH_SESSION_TTL_DAYS", "7"),
            ("AUTH_SESSION_MAX_DAYS", "14"),
            ("AUTH_TRUSTED_PROXIES", "10.0.0.0/8, ::1,"),
            ("AUTH_LOCKOUT_THRESHOLD", "3"),
            ("AUTH_LOCKOUT_MINUTES", "5"),
            ("AUTH_LOCKOUT_MAX_MINUTES", "60"),
            ("AUTH_IP_FAILURE_LIMIT", "10"),
            ("AUTH_RATE_LIMIT_PER_MINUTE", "120"),
        ]))
        .expect("valid");
        assert!(config.registration_open());
        assert_eq!(config.setup_token(), Some("a-long-enough-setup-token"));
        assert_eq!(config.session_ttl(), TimeDelta::days(7));
        assert_eq!(config.session_max(), TimeDelta::days(14));
        let proxies: Vec<String> = config
            .trusted_proxies()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(proxies, ["10.0.0.0/8", "::1/128"]);
        assert_eq!(config.lockout_threshold(), 3);
        assert_eq!(config.lockout_duration(), TimeDelta::minutes(5));
        assert_eq!(config.lockout_max(), TimeDelta::minutes(60));
        assert_eq!(config.ip_failure_limit(), 10);
        assert_eq!(config.rate_limit_per_minute(), 120);
    }

    #[test]
    fn treats_blank_values_as_unset() {
        let config = AuthConfig::parse(&env(&[
            ("AUTH_SETUP_TOKEN", "   "),
            ("AUTH_SESSION_TTL_DAYS", ""),
        ]))
        .expect("valid");
        assert_eq!(config.setup_token(), None);
        assert_eq!(config.session_ttl(), TimeDelta::days(30));
    }

    #[test]
    fn reports_every_invalid_variable() {
        assert_eq!(
            fields(&[
                ("AUTH_REGISTRATION_OPEN", "yes"),
                ("AUTH_SESSION_TTL_DAYS", "0"),
                ("AUTH_TRUSTED_PROXIES", "10.0.0.0/8,proxy.local"),
                ("AUTH_LOCKOUT_THRESHOLD", "-1"),
                ("AUTH_IP_FAILURE_LIMIT", "many"),
                ("AUTH_RATE_LIMIT_PER_MINUTE", "0"),
            ]),
            [
                "AUTH_REGISTRATION_OPEN",
                "AUTH_SESSION_TTL_DAYS",
                "AUTH_TRUSTED_PROXIES",
                "AUTH_LOCKOUT_THRESHOLD",
                "AUTH_IP_FAILURE_LIMIT",
                "AUTH_RATE_LIMIT_PER_MINUTE",
            ]
        );
    }

    #[test]
    fn requires_the_absolute_lifetime_to_cover_the_sliding_one() {
        assert_eq!(
            fields(&[
                ("AUTH_SESSION_TTL_DAYS", "60"),
                ("AUTH_SESSION_MAX_DAYS", "30")
            ]),
            ["AUTH_SESSION_MAX_DAYS"]
        );
        assert_eq!(
            fields(&[("AUTH_SESSION_MAX_DAYS", "3651")]),
            ["AUTH_SESSION_MAX_DAYS"]
        );
    }

    #[test]
    fn requires_the_longest_lockout_to_cover_the_first() {
        assert_eq!(
            fields(&[
                ("AUTH_LOCKOUT_MINUTES", "30"),
                ("AUTH_LOCKOUT_MAX_MINUTES", "20")
            ]),
            ["AUTH_LOCKOUT_MAX_MINUTES"]
        );
        assert_eq!(
            fields(&[("AUTH_LOCKOUT_MINUTES", "0")]),
            ["AUTH_LOCKOUT_MINUTES"]
        );
    }

    #[test]
    fn rejects_weak_setup_tokens() {
        assert_eq!(
            fields(&[("AUTH_SETUP_TOKEN", "short")]),
            ["AUTH_SETUP_TOKEN"]
        );
        assert_eq!(
            fields(&[("AUTH_SETUP_TOKEN", "has a space in the middle")]),
            ["AUTH_SETUP_TOKEN"]
        );
    }

    #[test]
    fn error_message_is_a_dotted_key_with_the_variables() {
        let error = AuthConfig::parse(&env(&[
            ("AUTH_LOCKOUT_THRESHOLD", "0"),
            ("AUTH_SETUP_TOKEN", "short"),
        ]))
        .expect_err("invalid");
        assert_eq!(
            error.to_string(),
            "rustauth.config.invalid AUTH_SETUP_TOKEN, AUTH_LOCKOUT_THRESHOLD"
        );
    }

    #[test]
    fn accepts_borrowed_maps() {
        let env: HashMap<&str, &str> = HashMap::from([("AUTH_REGISTRATION_OPEN", "true")]);
        assert!(AuthConfig::parse(&env).expect("valid").registration_open());
    }

    #[test]
    fn builder_validates_settings_without_variables() {
        let error = AuthConfig::builder()
            .failure_window(TimeDelta::zero())
            .touch_interval(TimeDelta::seconds(-1))
            .build()
            .expect_err("invalid");
        assert_eq!(error.fields, ["failure_window", "touch_interval"]);
        let config = AuthConfig::builder()
            .registration_open(true)
            .session_ttl(TimeDelta::hours(1))
            .session_max(TimeDelta::hours(2))
            .build()
            .expect("valid");
        assert_eq!(config.session_ttl(), TimeDelta::hours(1));
    }

    #[test]
    fn debug_hides_the_setup_token() {
        let config = AuthConfig::builder()
            .setup_token("a-long-enough-setup-token")
            .build()
            .expect("valid");
        let debug = format!("{config:?}");
        assert!(!debug.contains("a-long-enough-setup-token"));
        assert!(debug.contains("***"));
    }
}
