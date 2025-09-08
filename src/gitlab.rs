use crate::Detector;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    Missing(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Missing(what) => write!(f, "ID token variable not found: {what}"),
        }
    }
}

pub(crate) struct GitLabCI;

impl GitLabCI {
    /// Normalizes an audience string into the format required
    /// for GitLab CI ID token environment variables.
    ///
    /// Specifically, this uppercases all alphanumeric characters
    /// and replaces all non-alphanumeric characters with underscores.
    ///
    /// For example, "sigstore" becomes "SIGSTORE",
    /// and "http://test.audience" becomes "HTTP___TEST_AUDIENCE".
    fn normalized_audience(audience: &str) -> String {
        audience
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect()
    }
}

impl Detector for GitLabCI {
    type Error = Error;

    fn new() -> Option<Self> {
        std::env::var("GITLAB_CI")
            .ok()
            // Per GitLab docs, this is exactly "true" when
            // running in GitLab CI.
            .filter(|v| v == "true")
            .map(|_| GitLabCI)
    }

    /// On GitLab CI, the OIDC token URL is provided via an environment variable.
    /// Specifically, we look for `<AUD>_ID_TOKEN` where `<AUD>` is the
    /// audience, uppercased and with non-ASCII-alphanumeric characters replaced by `_`.
    ///
    /// As an example, audience "sigstore" would require variable SIGSTORE_ID_TOKEN,
    /// and audience "http://test.audience" would require variable
    /// HTTP___TEST_AUDIENCE_ID_TOKEN.
    async fn detect(&self, audience: &str) -> Result<crate::IdToken, Self::Error> {
        let normalized_audience = Self::normalized_audience(audience);

        let var_name = format!("{normalized_audience}_ID_TOKEN");
        let token = std::env::var(&var_name).map_err(|_| Error::Missing(var_name))?;

        Ok(crate::IdToken(token.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::GitLabCI;

    #[test]
    fn test_normalized_audience() {
        let cases = [
            ("sigstore", "SIGSTORE"),
            ("http://test.audience", "HTTP___TEST_AUDIENCE"),
            ("my-audience_123", "MY_AUDIENCE_123"),
            ("Audience With Spaces!", "AUDIENCE_WITH_SPACES_"),
            // TODO(ww): This mirrors what `id` does, but maybe we should
            // reject audiences with non-ASCII characters? Or reject those
            // that normalize to only underscores?
            ("😭", "_"),
            ("😭😭😭", "___"),
        ];

        for (input, expected) in cases {
            assert_eq!(GitLabCI::normalized_audience(input), expected);
        }
    }
}
