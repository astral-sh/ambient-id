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
    /// An environment variable delta.
    enum EnvDelta {
        /// Set an environment variable to a value.
        Add(String, String),
        /// Unset an environment variable.
        Remove(String),
    }

    /// A RAII guard for setting and unsetting environment variables.
    ///
    /// This maintains a stack of changes to unwind on drop; changes
    /// are unwound the reverse order of application
    pub(crate) struct EnvScope {
        changes: Vec<EnvDelta>,
    }

    impl EnvScope {
        pub fn new() -> Self {
            EnvScope { changes: vec![] }
        }

        /// Sets an environment variable for the duration of this scope.
        #[allow(unsafe_code)]
        pub fn setenv(&mut self, key: &str, value: &str) {
            match std::env::var(key) {
                // Key was set before; restore old value on drop.
                Ok(old) => self.changes.push(EnvDelta::Add(key.to_string(), old)),
                // Key was not set before; remove it on drop.
                Err(_) => self.changes.push(EnvDelta::Remove(key.to_string())),
            }

            unsafe { std::env::set_var(key, value) };
        }

        /// Removes an environment variable for the duration of this scope.
        #[allow(unsafe_code)]
        pub fn unsetenv(&mut self, key: &str) {
            match std::env::var(key) {
                // Key was set before; restore old value on drop.
                Ok(old) => self.changes.push(EnvDelta::Add(key.to_string(), old)),
                // Key was not set before; nothing to do.
                Err(_) => {}
            }

            unsafe { std::env::remove_var(key) };
        }
    }

    impl Drop for EnvScope {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // Unwind changes in reverse order.
            for change in self.changes.drain(..).rev() {
                match change {
                    EnvDelta::Add(key, value) => unsafe { std::env::set_var(key, value) },
                    EnvDelta::Remove(key) => unsafe { std::env::remove_var(key) },
                }
            }
        }
    }

    #[tokio::test]
    async fn test_no_detection() {
        let mut scope = EnvScope::new();
        scope.unsetenv("GITHUB_ACTIONS");
        scope.unsetenv("GITLAB_CI");

        assert!(
            super::detect("bupkis")
                .await
                .expect("should not error")
                .is_none()
        );
    }
}
