//! Value objects that validate on construction: `UserId`, `Username`, `DisplayName`, `Password`,
//! `Role`, `SessionId`, `SessionToken`, `TokenHash`, `ClientInfo`, `AuthMethod`, and `Assurance`.
//!
//! Secrets (`Password`, `SessionToken`) redact themselves in `Debug` and are never logged.
