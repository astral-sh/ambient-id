//! Detects ambient OIDC credentials in a variety of environments.

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

use secrecy::{ExposeSecret, SecretString};

mod github;
mod gitlab;

/// A detected ID token.
pub struct IdToken(SecretString);

impl IdToken {
    /// Reveals the detected ID token.
    pub fn reveal(&self) -> &str {
        self.0.expose_secret()
    }
}

/// Errors that can occur during detection.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error occurred while detecting GitHub Actions credentials.
    #[error("GitHub Actions detection error: {0}")]
    GitHubActions(#[from] github::Error),
    /// An error occurred while detecting GitLab CI credentials.
    #[error("GitLab CI detection error: {0}")]
    GitLabCI(#[from] gitlab::Error),
}

/// A trait for detecting ambient OIDC credentials.
trait Detector {
    type Error;

    fn new() -> Option<Self>
    where
        Self: Sized;

    async fn detect(&self, audience: &str) -> Result<IdToken, Self::Error>;
}

/// Detects ambient OIDC credentials in the current environment.
///
/// The given `audience` controls the `aud` claim in the returned ID token.
///
/// This function runs a series of detection strategies and returns
/// the first successful one. If no credentials are found,
/// it returns `Ok(None)`.
///
/// If any (hard) errors occur during detection, it returns `Err`.
pub async fn detect(audience: &str) -> Result<Option<IdToken>, Error> {
    macro_rules! detect {
        ($detector:path) => {
            if let Some(detector) = <$detector>::new() {
                detector.detect(audience).await.map_err(Into::into).map(Some)
            } else {
                Ok(None)
            }
        };
        ($detector:path, $($rest:path),+) => {
            if let Some(detector) = <$detector>::new() {
                detector.detect(audience).await.map_err(Into::into).map(Some)
            } else {
                detect!($($rest),+)
            }
        };
    }

    detect!(github::GitHubActions, gitlab::GitLabCI)
}

#[cfg(test)]
mod tests {
    enum EnvChange {
        Add(String, String),
        Remove(String),
    }

    pub(crate) struct EnvScope {
        changes: Vec<EnvChange>,
    }

    impl EnvScope {
        pub fn new() -> Self {
            EnvScope { changes: vec![] }
        }

        /// Sets an environment variable for the duration of this scope.
        #[allow(unsafe_code)]
        pub fn setenv(&mut self, key: &str, value: &str) {
            match std::env::var(key) {
                Ok(old) => self.changes.push(EnvChange::Add(key.to_string(), old)),
                Err(_) => self.changes.push(EnvChange::Remove(key.to_string())),
            }

            unsafe { std::env::set_var(key, value) };
        }

        /// Removes an environment variable for the duration of this scope.
        #[allow(unsafe_code)]
        pub fn unsetenv(&mut self, key: &str) {
            match std::env::var(key) {
                Ok(old) => self.changes.push(EnvChange::Add(key.to_string(), old)),
                Err(_) => {}
            }

            unsafe { std::env::remove_var(key) };
        }
    }

    impl Drop for EnvScope {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            for change in self.changes.drain(..).rev() {
                match change {
                    EnvChange::Add(key, value) => unsafe { std::env::set_var(key, value) },
                    EnvChange::Remove(key) => unsafe { std::env::remove_var(key) },
                }
            }
        }
    }
}
