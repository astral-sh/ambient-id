//! Google Cloud Platform OIDC token detection.

use reqwest_middleware::ClientWithMiddleware;
use serde::ser;
use thiserror::Error;

use crate::DetectionStrategy;

const GCP_PRODUCT_NAME_FILE: &str = "/sys/class/dmi/id/product_name";
const GCP_TOKEN_REQUEST_URL: &str =
    "http://metadata/computeMetadata/v1/instance/service-accounts/default/token";
const GCP_IDENTITY_REQUEST_URL: &str =
    "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity";
const GCP_GENERATEIDTOKEN_REQUEST_URL_TEMPLATE: &str =
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:generateIdToken";

const GCP_PRODUCT_NAMES: &[&str] = &["Google", "Google Compute Engine"];

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid GOOGLE_SERVICE_ACCOUNT_NAME value: {0:?}")]
    ServiceAccountNameInvalid(std::ffi::OsString),
    #[error("failed to request access token")]
    AccessTokenRequest(#[source] reqwest_middleware::Error),
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

            if GCP_PRODUCT_NAMES.contains(&product_name.as_str()) {
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
                    .header("Metadata-Flavor", "Google")
                    .send()
                    .await
                    .map_err(|e| Error::AccessTokenRequest(e.into()))?
                    .error_for_status()
                    .map_err(|e| Error::AccessTokenRequest(e.into()))?
                    .json::<AccessTokenResponse>()
                    .await
                    .map_err(|e| Error::AccessTokenRequest(e.into()))?;

                // Use the access token to request an ID token for the specified service account.
                let id_token_request_url = format!(
                    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{service_account_name}:generateIdToken"
                );

                todo!()
            }
            GcpSubstrategy::Direct => todo!(),
        }
    }
}
