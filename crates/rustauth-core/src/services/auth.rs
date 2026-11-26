//! `AuthService`: first-run setup, registration, sign-in, request verification, the caller's
//! own profile and password, and session management.

use chrono::{DateTime, Utc};

use crate::config::AuthConfig;
use crate::entities::{
    NewPassword, NewUser, PasswordCredential, Principal, RegisterPolicy, Session, Subject, User,
    UserPatch,
};
use crate::error::{AuthError, AuthResult};
use crate::ports::Ports;
use crate::services::guard::{LoginGuard, Slot};
use crate::services::inputs::{Registration, SetupStatus, SignedIn};
use crate::values::{
    Assurance, AuthMethod, ClientInfo, DisplayName, Password, Role, SessionId, TokenHash, UserId,
    Username,
};

pub struct AuthService {
    ports: Ports,
    config: AuthConfig,
    guard: LoginGuard,
    /// Hash of the setup token (configured or generated), compared in constant time.
    setup: TokenHash,
    /// A real hash of a random password: unknown usernames are verified against it so they cost
    /// the same hashing time as real accounts.
    dummy: String,
}

impl AuthService {
    /// Prepares the service: hashes the setup token (generating one when the configuration has
    /// none) and computes the dummy hash. A generated token is logged once
    /// (`rustauth.setup.token-issued`) while no account exists, so the operator can create the
    /// first one. With several instances, configure `AUTH_SETUP_TOKEN` instead: each instance
    /// would generate its own.
    pub async fn new(ports: Ports, config: AuthConfig) -> AuthResult<Self> {
        let (setup, generated) = match config.setup_token() {
            Some(token) => (ports.tokens.hash(token), None),
            None => {
                let (token, hash) = ports.tokens.issue();
                (hash, Some(token))
            }
        };
        let (filler, _) = ports.tokens.issue();
        let dummy = ports
            .hasher
            .hash(&Password::candidate(filler.expose().to_owned()))
            .await?;
        if let Some(token) = generated
            && ports.users.count().await? == 0
        {
            tracing::info!(setup_token = token.expose(), "rustauth.setup.token-issued");
        }
        let guard = LoginGuard::new(ports.users.clone(), ports.clock.clone(), &config);
        Ok(Self {
            ports,
            config,
            guard,
            setup,
            dummy,
        })
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Whether the first account still has to be created, and whether sign-ups are open.
    pub async fn setup_status(&self) -> AuthResult<SetupStatus> {
        Ok(SetupStatus {
            needs_setup: self.ports.users.count().await? == 0,
            registration_open: self.config.registration_open(),
        })
    }

    /// Creates an account and signs it in. While no account exists, `setup_token` must match and
    /// the account becomes an administrator; afterwards registration must be open and creates
    /// plain users. The repository makes the final decision inside its lock.
    pub async fn register(
        &self,
        input: Registration,
        setup_token: Option<&str>,
        client: &ClientInfo,
    ) -> AuthResult<SignedIn> {
        let policy = RegisterPolicy {
            registration_open: self.config.registration_open(),
            setup_token_ok: setup_token
                .is_some_and(|token| self.ports.tokens.hash(token).matches(&self.setup)),
        };
        // Fail early, before spending hashing work; the repository checks again under its lock.
        policy.decide(self.ports.users.count().await?)?;
        let now = self.ports.clock.now();
        let hash = self.ports.hasher.hash(&input.password).await?;
        let user = self
            .ports
            .users
            .register(
                NewUser {
                    id: UserId::generate(),
                    username: input.username,
                    display_name: input.display_name,
                    role: Role::User,
                    created_at: now,
                },
                NewPassword {
                    hash,
                    changed_at: now,
                },
                policy,
            )
            .await?;
        tracing::info!(user_id = %user.id, role = %user.role, "rustauth.user.registered");
        self.start(user, client).await
    }

    /// Signs in with a username and password. Unknown usernames verify against the dummy hash
    /// and fail with the same error, and locked accounts (or unknown usernames) are refused
    /// before the password is checked. A disabled account fails with `Forbidden` only after the
    /// correct password. A password changed or reset while the check ran fails it with
    /// `InvalidCredentials`.
    pub async fn login(
        &self,
        username: &str,
        password: String,
        client: &ClientInfo,
    ) -> AuthResult<SignedIn> {
        let slot = self.guard.admit(client)?;
        let password = Password::candidate(password);
        let Ok(username) = Username::new(username) else {
            // No account can have an invalid username, so it is not tracked by name (where it
            // could only collide with a valid one).
            return Err(self.reject(&password, slot).await);
        };
        let found = self.ports.users.find(&username).await?;
        let subject = match &found {
            Some((user, _)) => Subject::User(user.id),
            None => Subject::Name(username),
        };
        let seen = match self.guard.begin(&subject).await {
            // Deleted since it was found: answer as for any unknown username.
            Err(AuthError::NotFound { .. }) => return Err(self.reject(&password, slot).await),
            other => other?,
        };
        let Some((user, credential)) = found else {
            self.matches(&password, None).await?;
            slot.keep();
            return Err(self.guard.fail(client, &subject, seen).await);
        };
        if !self.matches(&password, credential.as_ref()).await? {
            slot.keep();
            return Err(self.guard.fail(client, &subject, seen).await);
        }
        let signed = match self
            .complete(&subject, user, credential.as_ref(), client)
            .await
        {
            // Deleted during the check: answer as for any unknown username.
            Err(AuthError::NotFound { .. }) => Err(AuthError::InvalidCredentials),
            other => other,
        }?;
        tracing::info!(user_id = %signed.user.id, ip = ?client.ip(), "rustauth.login.succeeded");
        Ok(signed)
    }

    /// The rest of a sign-in after the correct password: clears the failures (a lock set during
    /// the check wins), refuses a disabled account, and issues the session, unless the verified
    /// password was replaced in the meantime.
    async fn complete(
        &self,
        subject: &Subject,
        user: User,
        verified: Option<&PasswordCredential>,
        client: &ClientInfo,
    ) -> AuthResult<SignedIn> {
        self.guard.succeed(subject).await?;
        if user.is_disabled() {
            return Err(AuthError::forbidden("This account is disabled."));
        }
        let signed = self.start(user, client).await?;
        self.confirm(&signed, verified).await?;
        Ok(signed)
    }

    /// Withdraws a new session whose password was changed or reset while the sign-in checked
    /// it: that change revoked the account's sessions before this one existed. The credential is
    /// read after the session is stored, so a change that lands later revokes it itself, and no
    /// sign-in with a replaced password keeps a session.
    async fn confirm(
        &self,
        signed: &SignedIn,
        verified: Option<&PasswordCredential>,
    ) -> AuthResult<()> {
        let current = self.ports.users.find(&signed.user.username).await?;
        let unchanged = current.is_some_and(|(user, credential)| {
            user.id == signed.user.id
                && credential.as_ref().map(|stored| stored.hash.as_str())
                    == verified.map(|stored| stored.hash.as_str())
        });
        if unchanged {
            return Ok(());
        }
        self.ports
            .sessions
            .delete(signed.user.id, signed.session.id)
            .await?;
        tracing::info!(
            user_id = %signed.user.id,
            session_id = %signed.session.id,
            "rustauth.login.superseded"
        );
        Err(AuthError::InvalidCredentials)
    }

    /// Fails an attempt that has no lockout of its own: it still costs the dummy check (so the
    /// time spent reveals nothing) and counts against the client IP.
    async fn reject(&self, password: &Password, slot: Slot<'_>) -> AuthError {
        if let Err(error) = self.matches(password, None).await {
            return error;
        }
        slot.keep();
        AuthError::InvalidCredentials
    }

    /// Revokes the caller's current session.
    pub async fn logout(&self, principal: &Principal) -> AuthResult<()> {
        self.ports
            .sessions
            .delete(principal.user_id, principal.session_id)
            .await?;
        tracing::info!(
            user_id = %principal.user_id,
            session_id = %principal.session_id,
            "rustauth.session.revoked"
        );
        Ok(())
    }

    /// Checks a bearer token: hashes it, loads the session with its user, and rejects expired
    /// sessions and disabled or deleted users. A session used more than the touch interval (an
    /// hour) after its last write slides forward: `ttl` from now, never past `max` from creation.
    pub async fn verify(&self, bearer: &str) -> AuthResult<Principal> {
        if bearer.is_empty() {
            return Err(AuthError::Unauthorized);
        }
        let hash = self.ports.tokens.hash(bearer);
        let Some((session, user)) = self.ports.sessions.find(&hash).await? else {
            return Err(AuthError::Unauthorized);
        };
        let now = self.ports.clock.now();
        if !session.is_active(now, self.config.session_max()) || user.is_disabled() {
            return Err(AuthError::Unauthorized);
        }
        if now - session.last_used_at >= self.config.touch_interval() {
            let expires_at = self.expiry(session.created_at, now);
            // A failed touch only delays the slide; the request itself is valid.
            if let Err(error) = self.ports.sessions.touch(session.id, now, expires_at).await {
                tracing::warn!(
                    error = %error,
                    session_id = %session.id,
                    "rustauth.session.touch-failed"
                );
            }
        }
        Ok(Principal {
            user_id: user.id,
            username: user.username,
            role: user.role,
            session_id: session.id,
            assurance: session.assurance,
        })
    }

    /// The caller's account.
    pub async fn me(&self, principal: &Principal) -> AuthResult<User> {
        self.ports
            .users
            .get(principal.user_id)
            .await?
            .ok_or(AuthError::Unauthorized)
    }

    /// Changes the caller's display name.
    pub async fn update_profile(
        &self,
        principal: &Principal,
        display_name: DisplayName,
    ) -> AuthResult<User> {
        let patch = UserPatch {
            display_name: Some(display_name),
            ..UserPatch::default()
        };
        let now = self.ports.clock.now();
        self.ports
            .users
            .update(principal.user_id, &patch, now)
            .await
    }

    /// Changes the caller's password after checking the current one, and revokes the caller's
    /// other sessions (the current one stays). A wrong current password counts toward the
    /// account lockout and fails as a validation error on `current`, so clients do not mistake
    /// it for an expired session.
    pub async fn change_password(
        &self,
        principal: &Principal,
        current: String,
        new: Password,
        client: &ClientInfo,
    ) -> AuthResult<()> {
        let slot = self.guard.admit(client)?;
        let Some((user, credential)) = self
            .ports
            .users
            .find(&principal.username)
            .await?
            .filter(|(user, _)| user.id == principal.user_id)
        else {
            return Err(AuthError::Unauthorized);
        };
        // A missing account means the caller's session is stale.
        let stale = |error| match error {
            AuthError::NotFound { .. } => AuthError::Unauthorized,
            other => other,
        };
        let subject = Subject::User(user.id);
        let seen = self.guard.begin(&subject).await.map_err(stale)?;
        let current = Password::candidate(current);
        if !self.matches(&current, credential.as_ref()).await? {
            slot.keep();
            return Err(match self.guard.fail(client, &subject, seen).await {
                AuthError::InvalidCredentials => {
                    AuthError::validation("current", "Current password is incorrect.")
                }
                other => other,
            });
        }
        self.guard.succeed(&subject).await.map_err(stale)?;
        let now = self.ports.clock.now();
        let hash = self.ports.hasher.hash(&new).await?;
        self.ports.users.set_password(user.id, hash, now).await?;
        let revoked = self
            .ports
            .sessions
            .delete_all(user.id, Some(principal.session_id))
            .await?;
        tracing::info!(user_id = %user.id, revoked, "rustauth.password.changed");
        Ok(())
    }

    /// The caller's active sessions, most recently used first. Compare `id` with
    /// `principal.session_id` to flag the current one.
    pub async fn sessions(&self, principal: &Principal) -> AuthResult<Vec<Session>> {
        let now = self.ports.clock.now();
        let max = self.config.session_max();
        let mut sessions: Vec<Session> = self
            .ports
            .sessions
            .list(principal.user_id)
            .await?
            .into_iter()
            .filter(|session| session.is_active(now, max))
            .collect();
        sessions.sort_by_key(|session| std::cmp::Reverse(session.last_used_at));
        Ok(sessions)
    }

    /// Revokes one of the caller's sessions (`NotFound` if it is not theirs).
    pub async fn revoke(&self, principal: &Principal, id: SessionId) -> AuthResult<()> {
        if !self.ports.sessions.delete(principal.user_id, id).await? {
            return Err(AuthError::not_found("Session"));
        }
        tracing::info!(user_id = %principal.user_id, session_id = %id, "rustauth.session.revoked");
        Ok(())
    }

    /// Revokes every session of the caller except the current one; returns how many.
    pub async fn revoke_others(&self, principal: &Principal) -> AuthResult<u64> {
        let revoked = self
            .ports
            .sessions
            .delete_all(principal.user_id, Some(principal.session_id))
            .await?;
        tracing::info!(user_id = %principal.user_id, revoked, "rustauth.session.revoked-others");
        Ok(revoked)
    }

    /// Deletes expired sessions and the sign-in failures of usernames without an account that
    /// no longer count ([`crate::Lockout::is_stale`]); returns how many rows in all.
    /// Applications call it periodically (hourly is plenty).
    pub async fn purge(&self) -> AuthResult<u64> {
        let now = self.ports.clock.now();
        let sessions = self.ports.sessions.purge_expired(now).await?;
        let names = self
            .ports
            .users
            .prune(now - self.config.failure_window())
            .await?;
        Ok(sessions + names)
    }

    /// Verifies `password` against the credential, or against the dummy hash when there is none
    /// (so the time spent does not reveal it).
    async fn matches(
        &self,
        password: &Password,
        credential: Option<&PasswordCredential>,
    ) -> AuthResult<bool> {
        match credential {
            Some(credential) => self.ports.hasher.verify(password, &credential.hash).await,
            None => {
                self.ports.hasher.verify(password, &self.dummy).await?;
                Ok(false)
            }
        }
    }

    /// Issues a session for `user`.
    async fn start(&self, user: User, client: &ClientInfo) -> AuthResult<SignedIn> {
        let now = self.ports.clock.now();
        let (token, token_hash) = self.ports.tokens.issue();
        let session = Session {
            id: SessionId::generate(),
            user_id: user.id,
            token_hash,
            methods: vec![AuthMethod::Password],
            assurance: Assurance::Aal1,
            created_at: now,
            last_used_at: now,
            expires_at: self.expiry(now, now),
            user_agent: client.user_agent().to_owned(),
            ip: client.ip(),
        };
        self.ports.sessions.insert(&session).await?;
        tracing::info!(user_id = %user.id, session_id = %session.id, "rustauth.session.created");
        Ok(SignedIn {
            token,
            session,
            user,
        })
    }

    /// The sliding expiry at `now`, capped by the absolute lifetime from `created_at`.
    fn expiry(&self, created_at: DateTime<Utc>, now: DateTime<Utc>) -> DateTime<Utc> {
        (now + self.config.session_ttl()).min(created_at + self.config.session_max())
    }
}

#[cfg(test)]
mod races;
#[cfg(test)]
mod tests;
