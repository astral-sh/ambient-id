//! Google Cloud Platform OIDC token detection.

use reqwest_middleware::ClientWithMiddleware;
use serde_json::json;
use thiserror::Error;

use crate::{DetectionStrategy, IdToken};

const GCP_PRODUCT_NAME_FILE: &str = "/sys/class/dmi/id/product_name";
const GCP_TOKEN_REQUEST_URL: &str =
    "http://metadata/computeMetadata/v1/instance/service-accounts/default/token";
const GCP_IDENTITY_REQUEST_URL: &str =
    "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity";

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
