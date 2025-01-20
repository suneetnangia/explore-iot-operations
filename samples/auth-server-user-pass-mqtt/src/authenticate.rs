// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::http::{ParsedRequest, Response, API_SUPPORTED_VERSION, HTTP_MIME_APPLICATION_JSON};
use anyhow::Result;
use hyper::{header, Method, StatusCode};
use log::trace;
use openssl::x509::X509;
use std::collections::HashMap;

/// Returned when the client requests an invalid API version. Contains a list of
/// supported API versions.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportedApiVersions {
    /// List of supported API versions.
    supported_versions: Vec<String>,
}

impl Default for SupportedApiVersions {
    fn default() -> Self {
        SupportedApiVersions {
            supported_versions: vec![API_SUPPORTED_VERSION.to_string()],
        }
    }
}

/// Authenticate the connecting MQTT client.
pub(crate) async fn authenticate(req: ParsedRequest) -> Result<Response> {
    // Check that the request follows the authentication spec.
    if req.method != Method::POST {
        return Ok(Response::method_not_allowed(&req.method));
    }

    if let Some(content_type) = req.headers.get(header::CONTENT_TYPE.as_str()) {
        if content_type.to_lowercase() != HTTP_MIME_APPLICATION_JSON {
            return Ok(Response::bad_request(format!(
                "invalid content-type: {content_type}"
            )));
        }
    }

    let Some(body) = req.body else {
        return Ok(Response::bad_request("missing body"));
    };

    if req.path != "/" {
        return Ok(Response::not_found(format!("{} not found", req.path)));
    }

    if let Some(api_version) = req.query.get("api-version") {
        // Currently, the custom auth API supports only version 0.5.0.
        if api_version != API_SUPPORTED_VERSION {
            return Response::json(
                StatusCode::UNPROCESSABLE_ENTITY,
                SupportedApiVersions::default(),
            );
        }
    } else {
        return Ok(Response::bad_request("missing api-version"));
    }

    let body: ClientAuthRequest = match serde_json::from_str(&body) {
        Ok(body) => body,
        Err(err) => {
            return Ok(Response::bad_request(format!(
                "invalid client request body: {err}"
            )))
        }
    };

    let auth_response = auth_client(body).await?;

    let response = match auth_response {
        ClientAuthResponse::Allow(response) => Response::json(StatusCode::OK, response).expect("Failed to create response"),
        ClientAuthResponse::Deny { reason } => {
            let body = serde_json::json!({
                "reason": reason,
            });
            Response::json(StatusCode::FORBIDDEN, body).expect("Failed to create response")
        }
    };

    Ok(response)
}

/// MQTT client authentication request. Contains the information from either a CONNECT
/// or AUTH packet.
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ClientAuthRequest {
    /// Data from an MQTT CONNECT packet.
    #[serde(alias = "connect", rename_all = "camelCase")]
    Connect {
        /// Username, if provided.
        username: Option<String>,

        /// Password, if provided.
        password: Option<String>,

        /// Client certificate chain, if provided.
        #[serde(default, deserialize_with = "deserialize_cert_chain")]
        certs: Option<Vec<X509>>,

        /// Enhanced authentication data, if provided.
        enhanced_authentication: Option<EnhancedAuthentication>,
    },

    #[serde(alias = "auth", rename_all = "camelCase")]
    Auth {
        /// Enhanced authentication data, if provided.
        enhanced_authentication: EnhancedAuthentication,
    },
}

/// Fields from MQTT v5 enhanced authentication.
#[derive(Debug, serde::Deserialize)]
struct EnhancedAuthentication {
    /// Enhanced authentication method.
    method: String,

    /// Enhanced authentication data.
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
}

fn deserialize_cert_chain<'de, D>(deserializer: D) -> Result<Option<Vec<X509>>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let certs: Option<String> = serde::Deserialize::deserialize(deserializer)?;

    if let Some(certs) = certs {
        let certs = X509::stack_from_pem(certs.as_bytes()).map_err(|err| {
            serde::de::Error::invalid_type(
                serde::de::Unexpected::Other(&err.to_string()),
                &"pem-encoded cert",
            )
        })?;

        Ok(Some(certs))
    } else {
        Ok(None)
    }
}

enum ClientAuthResponse {
    /// Allow the connection. Translates to a CONNACK packet with reason = success.
    Allow(AuthPassResponse),

    /// Deny the connection. Translates to a CONNACK packet with the given reason code.
    Deny { reason: u8 },
}

/// Response to an authenticated client.
#[derive(Debug, serde::Serialize)]
struct AuthPassResponse {
    /// RFC 3339 timestamp that states the expiry time for the client's
    /// provided credentials. Clients will be disconnected when the expiry time passes.
    /// Omit `expiry` to allow clients to remain connected indefinitely.
    #[serde(skip_serializing_if = "Option::is_none")]
    expiry: Option<String>,

    /// The client's authorization attributes.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    attributes: HashMap<String, String>,
}

/// Authenticate the client based on the provided credentials.
async fn auth_client(body: ClientAuthRequest) -> Result<ClientAuthResponse> {
    match body {
        ClientAuthRequest::Connect {
            username,
            password,
            certs,
            enhanced_authentication,
        } => {
            // Note that password and enhanced authentication data are base64-encoded.
            trace!("Received MQTT CONNECT; username: {username:?}, password: {password:?}, enhancedAuthentication: {enhanced_authentication:?}");

            // TODO: Authenticate the client with provided certs. For now, this just logs the certs.
            if let Some(certs) = certs {
                trace!("Client certs found: {certs:#?}");
            }

            // TODO: Get attributes associated with the presented certificate. For now, this template
            // just provides hardcoded example values.
            let mut example_attributes = HashMap::new();
            example_attributes.insert("example_key".to_string(), "example_value".to_string());

            Ok(authentication_example(
                username.as_deref(),
                example_attributes,
            ))
        }

        ClientAuthRequest::Auth {
            enhanced_authentication,
        } => {
            // TODO: Authenticate the client with provided credentials. For now, this template just logs the
            // credentials. Note that password and enhanced authentication data are base64-encoded.
            println!("Got MQTT AUTH; enhancedAuthentication: {enhanced_authentication:?}");

            // Decode enhanced authentication method as 'username'.
            let engine = base64::engine::general_purpose::STANDARD;
            let method = enhanced_authentication.method;

            if let Ok(username) = base64::Engine::decode(&engine, method) {
                if let Ok(username) = std::str::from_utf8(&username) {
                    println!("Decoded enhanced authentication method: {username}");

                    // Enhanced authentication data is not used in this example, so silence the
                    // unused field warning.
                    let _ = enhanced_authentication.data;

                    Ok(authentication_example(Some(username), HashMap::new()))
                } else {
                    Ok(ClientAuthResponse::Deny { reason: 135 })
                }
            } else {
                println!("Failed to decode enhanced authentication method");

                Ok(ClientAuthResponse::Deny { reason: 135 })
            }
        }
    }
}

fn authentication_example(
    username: Option<&str>,
    attributes: HashMap<String, String>,
) -> ClientAuthResponse {
    // TODO: Determine when the client's credentials should expire. For now, this template sets
    // an expiry of 10 seconds if the username starts with 'expire'; otherwise, it does not set
    // expiry and allows clients to remain connected indefinitely.
    let example_expiry = username.and_then(|username| {
        if username.starts_with("expire") {
            let example_expiry = chrono::Utc::now()
                + chrono::TimeDelta::try_seconds(10).expect("invalid hardcoded time value");

            Some(example_expiry.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        } else {
            None
        }
    });

    // Example responses to client authentication. This template denies authentication to clients
    // who present usernames that begin with 'deny', but allows all others.
    if let Some(username) = username {
        if username.starts_with("deny") {
            return ClientAuthResponse::Deny { reason: 135 };
        }
    }

    ClientAuthResponse::Allow(AuthPassResponse {
        expiry: example_expiry,
        attributes,
    })
}
