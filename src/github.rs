use crate::Detector;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The GitHub Actions environment lacks necessary permissions.
    InsufficientPermissions(&'static str),
    /// The HTTP request to fetch the ID token failed.
    Request(#[from] reqwest::Error),
    InvalidResponse(#[from] serde_json::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InsufficientPermissions(what) => {
                write!(f, "insufficient permissions: {what}")
            }
            Error::Request(err) => write!(f, "HTTP request error: {err}"),
            Error::InvalidResponse(err) => write!(f, "invalid response: {err}"),
        }
    }
}

/// The JSON payload returned by GitHub's ID token endpoint.
#[derive(serde::Deserialize)]
struct TokenRequestResponse {
    value: String,
}

pub(crate) struct GitHubActions;

impl Detector for GitHubActions {
    type Error = Error;

    fn new() -> Option<Self> {
        std::env::var("GITHUB_ACTIONS")
            .ok()
            // Per GitHub docs, this is exactly "true" when
            // running in GitHub Actions.
            .filter(|v| v == "true")
            .map(|_| GitHubActions)
    }

    /// On GitHub Actions, the OIDC token URL is provided
    /// via the ACTIONS_ID_TOKEN_REQUEST_URL environment variable.
    /// We additionally need to fetch the ACTIONS_ID_TOKEN_REQUEST_TOKEN
    /// environment variable to authenticate the request.
    ///
    /// The absence of either variable indicates insufficient permissions.
    async fn detect(&self, audience: &str) -> Result<crate::IdToken, Self::Error> {
        let url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
            .map_err(|_| Error::InsufficientPermissions("missing ACTIONS_ID_TOKEN_REQUEST_URL"))?;
        let token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").map_err(|_| {
            Error::InsufficientPermissions("missing ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        })?;

        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .bearer_auth(token)
            .query(&[("audience", audience)])
            .send()
            .await?
            .error_for_status()?
            .json::<TokenRequestResponse>()
            .await?;

        Ok(crate::IdToken(resp.value.into()))
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use crate::Detector as _;

    use super::GitHubActions;

    /// Happy path for GitHub Actions OIDC token detection.
    #[tokio::test]
    #[cfg_attr(not(feature = "test-github-1p"), ignore)]
    async fn test_1p_github_actions_detection_ok() {
        let detector = GitHubActions::new().expect("should detect GitHub Actions");
        detector.detect("bupkis").await.expect("should fetch token");
    }

    // Sad path: we're in GitHub Actions, but `ACTIONS_ID_TOKEN_REQUEST_URL`
    // is unset.
    #[tokio::test]
    #[cfg_attr(not(feature = "test-github-1p"), ignore)]
    async fn test_1p_github_actions_detection_missing_url() {
        unsafe { std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_URL") };

        let detector = GitHubActions::new().expect("should detect GitHub Actions");

        match detector.detect("bupkis").await {
            Err(super::Error::InsufficientPermissions(what)) => {
                assert_eq!(what, "missing ACTIONS_ID_TOKEN_REQUEST_URL")
            }
            _ => panic!("expected insufficient permissions error"),
        }
    }

    /// Sad path: we're in GitHub Actions, but `ACTIONS_ID_TOKEN_REQUEST_TOKEN`
    /// is unset.
    #[tokio::test]
    #[cfg_attr(not(feature = "test-github-1p"), ignore)]
    async fn test_1p_github_actions_detection_missing_token() {
        unsafe { std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN") };

        let detector = GitHubActions::new().expect("should detect GitHub Actions");

        match detector.detect("bupkis").await {
            Err(super::Error::InsufficientPermissions(what)) => {
                assert_eq!(what, "missing ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            }
            _ => panic!("expected insufficient permissions error"),
        }
    }
}
