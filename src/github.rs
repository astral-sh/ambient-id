use crate::Detector;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The GitHub Actions environment lacks necessary permissions.
    InsufficientPermissions(&'static str),
    /// The HTTP request to fetch the ID token failed.
    Request(#[from] reqwest::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InsufficientPermissions(what) => {
                write!(f, "insufficient permissions: {what}")
            }
            Error::Request(err) => write!(f, "HTTP request failed: {err}"),
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
mod tests {
    use wiremock::{
        Mock, MockServer,
        matchers::{method, path},
    };

    use crate::{Detector as _, tests::EnvScope};

    use super::GitHubActions;

    /// Happy path for GitHub Actions OIDC token detection.
    #[tokio::test]
    #[cfg_attr(not(feature = "test-github-1p"), ignore)]
    async fn test_1p_detection_ok() {
        let detector = GitHubActions::new().expect("should detect GitHub Actions");
        detector.detect("bupkis").await.expect("should fetch token");
    }

    // Sad path: we're in GitHub Actions, but `ACTIONS_ID_TOKEN_REQUEST_URL`
    // is unset.
    #[tokio::test]
    #[cfg_attr(not(feature = "test-github-1p"), ignore)]
    async fn test_1p_detection_missing_url() {
        let mut scope = EnvScope::new();
        scope.unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL");

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
    async fn test_1p_detection_missing_token() {
        let mut scope = EnvScope::new();
        scope.unsetenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN");

        let detector = GitHubActions::new().expect("should detect GitHub Actions");

        match detector.detect("bupkis").await {
            Err(super::Error::InsufficientPermissions(what)) => {
                assert_eq!(what, "missing ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            }
            _ => panic!("expected insufficient permissions error"),
        }
    }

    #[test]
    fn test_not_detected() {
        let mut scope = EnvScope::new();
        scope.unsetenv("GITHUB_ACTIONS");

        assert!(GitHubActions::new().is_none());
    }

    #[test]
    fn test_detected() {
        let mut scope = EnvScope::new();
        scope.setenv("GITHUB_ACTIONS", "true");

        assert!(GitHubActions::new().is_some());
    }

    #[test]
    fn test_not_detected_wrong_value() {
        for value in &["", "false", "TRUE", "1", "yes"] {
            let mut scope = EnvScope::new();
            scope.setenv("GITHUB_ACTIONS", value);

            assert!(GitHubActions::new().is_none());
        }
    }

    #[tokio::test]
    async fn test_error_code() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let mut scope = EnvScope::new();
        scope.setenv("GITHUB_ACTIONS", "true");
        scope.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bogus");
        scope.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", &server.uri());

        let detector = GitHubActions::new().expect("should detect GitHub Actions");
        assert!(matches!(
            detector.detect("bupkis").await,
            Err(super::Error::Request(_))
        ));
    }

    #[tokio::test]
    async fn test_invalid_response() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "bogus": "response"
                })),
            )
            .mount(&server)
            .await;

        let mut scope = EnvScope::new();
        scope.setenv("GITHUB_ACTIONS", "true");
        scope.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bogus");
        scope.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", &server.uri());

        let detector = GitHubActions::new().expect("should detect GitHub Actions");
        assert!(matches!(
            detector.detect("bupkis").await,
            Err(super::Error::Request(_))
        ));
    }

    #[tokio::test]
    async fn test_ok() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": "the-token"
                })),
            )
            .mount(&server)
            .await;

        let mut scope = EnvScope::new();
        scope.setenv("GITHUB_ACTIONS", "true");
        scope.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bogus");
        scope.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", &server.uri());

        let detector = GitHubActions::new().expect("should detect GitHub Actions");
        let token = detector.detect("bupkis").await.expect("should fetch token");

        assert_eq!(token.reveal(), "the-token");
    }
}
