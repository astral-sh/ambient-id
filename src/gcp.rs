//! Google Cloud Platform OIDC token detection.

use reqwest_middleware::ClientWithMiddleware;
use serde_json::json;
use thiserror::Error;

use crate::{DetectionStrategy, IdToken};

const GCP_PRODUCT_NAME_FILE: &str = "/sys/class/dmi/id/product_name";
const GCP_TOKEN_REQUEST_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
const GCP_IDENTITY_REQUEST_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity";

const GCP_PRODUCT_NAMES: &[&str] = &["Google", "Google Compute Engine"];

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid GOOGLE_SERVICE_ACCOUNT_NAME value: {0:?}")]
    ServiceAccountNameInvalid(std::ffi::OsString),
    #[error("impersonation flow: failed to request access token")]
    AccessTokenRequest(#[source] reqwest_middleware::Error),
    #[error("impersonation flow: failed to exchange access token for ID token")]
    ExchangeIdTokenRequest(#[source] reqwest_middleware::Error),
    #[error("direct flow: failed to request ID token")]
    IdTokenRequest(#[source] reqwest_middleware::Error),
}

enum GcpSubstrategy {
    /// Obtain an ID token by impersonating the specified service account.
    Impersonation {
        service_account_name: std::ffi::OsString,
    },
    /// Obtain an ID token directly.
    Direct,
}

pub(crate) struct Gcp {
    client: ClientWithMiddleware,
    substrategy: GcpSubstrategy,
}

#[derive(serde::Deserialize)]
struct AccessTokenResponse {
    access_token: String,
}

#[derive(serde::Deserialize)]
struct GenerateIdTokenResponse {
    token: String,
}

impl DetectionStrategy for Gcp {
    type Error = Error;

    fn new(state: &crate::DetectionState) -> Option<Self>
    where
        Self: Sized,
    {
        if let Some(service_account_name) = std::env::var_os("GOOGLE_SERVICE_ACCOUNT_NAME") {
            Some(Self {
                client: state.client.clone(),
                substrategy: GcpSubstrategy::Impersonation {
                    service_account_name,
                },
            })
        } else {
            // Look for a well-known product name in the DMI product name file.
            let product_name = std::fs::read_to_string(GCP_PRODUCT_NAME_FILE).ok()?;

            if GCP_PRODUCT_NAMES.contains(&product_name.trim()) {
                Some(Self {
                    client: state.client.clone(),
                    substrategy: GcpSubstrategy::Direct,
                })
            } else {
                None
            }
        }
    }

    async fn detect(&self, audience: &str) -> Result<crate::IdToken, Self::Error> {
        match &self.substrategy {
            GcpSubstrategy::Impersonation {
                service_account_name,
            } => {
                let service_account_name = service_account_name.to_str().ok_or_else(|| {
                    Error::ServiceAccountNameInvalid(service_account_name.clone())
                })?;

                // Obtain an access token from the metadata server.
                let resp = self
                    .client
                    .get(GCP_TOKEN_REQUEST_URL)
                    .query(&[("scopes", "https://www.googleapis.com/auth/cloud-platform")])
                    .header("Metadata-Flavor", "Google")
                    .send()
                    .await
                    .map_err(Error::AccessTokenRequest)?
                    .error_for_status()
                    .map_err(|e| Error::AccessTokenRequest(e.into()))?
                    .json::<AccessTokenResponse>()
                    .await
                    .map_err(|e| Error::AccessTokenRequest(e.into()))?;

                // Use the access token to request an ID token for the specified service account.
                let id_token_request_url = format!(
                    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{service_account_name}:generateIdToken"
                );

                let resp = self
                    .client
                    .post(id_token_request_url)
                    .bearer_auth(resp.access_token)
                    .header("Content-Type", "application/json")
                    .body(
                        serde_json::to_string(&json!({
                            "audience": audience,
                            "includeEmail": true,
                        }))
                        .expect("impossible: JSON serialization failed"),
                    )
                    .send()
                    .await
                    .map_err(Error::ExchangeIdTokenRequest)?
                    .error_for_status()
                    .map_err(|e| Error::ExchangeIdTokenRequest(e.into()))?
                    .json::<GenerateIdTokenResponse>()
                    .await
                    .map_err(|e| Error::ExchangeIdTokenRequest(e.into()))?;

                Ok(IdToken(resp.token.into()))
            }
            GcpSubstrategy::Direct => {
                // Request an ID token directly from the metadata server.
                let resp = self
                    .client
                    .get(GCP_IDENTITY_REQUEST_URL)
                    .header("Metadata-Flavor", "Google")
                    .query(&[("audience", audience), ("format", "full")])
                    .send()
                    .await
                    .map_err(Error::IdTokenRequest)?
                    .error_for_status()
                    .map_err(|e| Error::IdTokenRequest(e.into()))?
                    .text()
                    .await
                    .map_err(|e| Error::IdTokenRequest(e.into()))?;

                Ok(IdToken(resp.into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer,
        matchers::{header, method, path, query_param},
    };

    use crate::{DetectionStrategy as _, tests::EnvScope};

    use super::Gcp;

    const TEST_SERVICE_ACCOUNT: &str = "test@example.iam.gserviceaccount.com";

    fn build_test_client(server: &MockServer) -> reqwest_middleware::ClientWithMiddleware {
        reqwest_middleware::ClientBuilder::new(
            reqwest::Client::builder()
                .resolve(
                    "metadata.google.internal",
                    std::net::SocketAddr::from(([127, 0, 0, 1], server.address().port())),
                )
                .build()
                .unwrap(),
        )
        .build()
    }

    #[tokio::test]
    async fn test_not_detected_no_env_no_file() {
        let mut scope = EnvScope::new();
        scope.unsetenv("GOOGLE_SERVICE_ACCOUNT_NAME");

        let state = Default::default();
        assert!(Gcp::new(&state).is_none());
    }

    #[tokio::test]
    async fn test_detected_impersonation() {
        let mut scope = EnvScope::new();
        scope.setenv("GOOGLE_SERVICE_ACCOUNT_NAME", TEST_SERVICE_ACCOUNT);

        let state = Default::default();
        assert!(Gcp::new(&state).is_some());
    }

    #[tokio::test]
    async fn test_direct_flow_ok() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/identity",
            ))
            .and(header("Metadata-Flavor", "Google"))
            .and(query_param("audience", "test_direct_flow_ok"))
            .and(query_param("format", "full"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("test-direct-token"))
            .mount(&server)
            .await;

        let detector = Gcp {
            client: build_test_client(&server),
            substrategy: super::GcpSubstrategy::Direct,
        };

        let token = detector.detect("test_direct_flow_ok").await.unwrap();
        assert_eq!(token.reveal(), "test-direct-token");
    }

    #[tokio::test]
    async fn test_direct_flow_error_code() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/identity",
            ))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let detector = Gcp {
            client: build_test_client(&server),
            substrategy: super::GcpSubstrategy::Direct,
        };

        assert!(matches!(
            detector.detect("test_direct_flow_error_code").await,
            Err(super::Error::IdTokenRequest(_))
        ));
    }

    #[tokio::test]
    async fn test_impersonation_flow_ok() {
        let metadata_server = MockServer::start().await;
        let iam_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .and(header("Metadata-Flavor", "Google"))
            .and(query_param(
                "scopes",
                "https://www.googleapis.com/auth/cloud-platform",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "test-access-token"
                })),
            )
            .mount(&metadata_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/projects/-/serviceAccounts/test@example.iam.gserviceaccount.com:generateIdToken"))
            .and(header("Authorization", "Bearer test-access-token"))
            .and(header("Content-Type", "application/json"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "token": "test-impersonation-token"
                })),
            )
            .mount(&iam_server)
            .await;

        let client = build_test_client(&metadata_server);

        let resp = client
            .get(format!(
                "{}/computeMetadata/v1/instance/service-accounts/default/token",
                metadata_server.uri()
            ))
            .query(&[("scopes", "https://www.googleapis.com/auth/cloud-platform")])
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .unwrap()
            .json::<super::AccessTokenResponse>()
            .await
            .unwrap();

        let token_resp = client
            .post(format!("{}/v1/projects/-/serviceAccounts/test@example.iam.gserviceaccount.com:generateIdToken", iam_server.uri()))
            .bearer_auth(resp.access_token)
            .header("Content-Type", "application/json")
            .body(
                serde_json::to_string(&json!({
                    "audience": "test_impersonation_flow_ok",
                    "includeEmail": true,
                }))
                .unwrap(),
            )
            .send()
            .await
            .unwrap()
            .json::<super::GenerateIdTokenResponse>()
            .await
            .unwrap();

        assert_eq!(token_resp.token, "test-impersonation-token");
    }

    #[tokio::test]
    async fn test_impersonation_flow_access_token_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let detector = Gcp {
            client: build_test_client(&server),
            substrategy: super::GcpSubstrategy::Impersonation {
                service_account_name: TEST_SERVICE_ACCOUNT.into(),
            },
        };

        assert!(matches!(
            detector
                .detect("test_impersonation_flow_access_token_error")
                .await,
            Err(super::Error::AccessTokenRequest(_))
        ));
    }

    #[tokio::test]
    async fn test_impersonation_flow_id_token_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "test-access-token"
                })),
            )
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/projects/-/serviceAccounts/test@example.iam.gserviceaccount.com:generateIdToken"))
            .respond_with(wiremock::ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let detector = Gcp {
            client: build_test_client(&server),
            substrategy: super::GcpSubstrategy::Impersonation {
                service_account_name: TEST_SERVICE_ACCOUNT.into(),
            },
        };

        assert!(matches!(
            detector
                .detect("test_impersonation_flow_id_token_error")
                .await,
            Err(super::Error::ExchangeIdTokenRequest(_))
        ));
    }

    #[tokio::test]
    async fn test_impersonation_flow_invalid_access_token_response() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "invalid": "response"
                })),
            )
            .mount(&server)
            .await;

        let detector = Gcp {
            client: build_test_client(&server),
            substrategy: super::GcpSubstrategy::Impersonation {
                service_account_name: TEST_SERVICE_ACCOUNT.into(),
            },
        };

        assert!(matches!(
            detector
                .detect("test_impersonation_flow_invalid_access_token_response")
                .await,
            Err(super::Error::AccessTokenRequest(_))
        ));
    }

    #[tokio::test]
    async fn test_impersonation_flow_invalid_id_token_response() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "test-access-token"
                })),
            )
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/projects/-/serviceAccounts/test@example.iam.gserviceaccount.com:generateIdToken"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "invalid": "response"
                })),
            )
            .mount(&server)
            .await;

        let detector = Gcp {
            client: build_test_client(&server),
            substrategy: super::GcpSubstrategy::Impersonation {
                service_account_name: TEST_SERVICE_ACCOUNT.into(),
            },
        };

        assert!(matches!(
            detector
                .detect("test_impersonation_flow_invalid_id_token_response")
                .await,
            Err(super::Error::ExchangeIdTokenRequest(_))
        ));
    }
}
