// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, header, Method, StatusCode};
use log::{info, trace};
use std::{
    collections::HashMap,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

pub(crate) type HttpRequest = hyper::Request<hyper::body::Incoming>;
pub(crate) type HttpResponse = hyper::Response<Full<Bytes>>;

// TODO: Can these moved to their own module?
pub(crate) const HTTP_MIME_APPLICATION_JSON: &str = "application/json";
pub(crate) const API_SUPPORTED_VERSION: &str = "0.5.0";

pub(crate) struct ParsedRequest {
    pub method: Method,
    pub version: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

impl ParsedRequest {
    pub(crate) async fn from_http(req: HttpRequest) -> Result<Self, Response> {
        let method = req.method().clone();
        let uri = req.uri();
        let path = uri.path().to_string();
        let version = format!("{:?}", req.version());

        let mut query = HashMap::new();
        if let Some(q) = req.uri().query() {
            let parts: Vec<&str> = q.split('&').collect();

            for p in parts {
                if let Some((key, value)) = p.split_once('=') {
                    query.insert(key.to_lowercase().to_string(), value.to_string());
                } else {
                    return Err(Response::bad_request("bad query value"));
                }
            }
        }

        let mut headers = HashMap::with_capacity(req.headers().len());
        for (key, value) in req.headers() {
            let key = key.to_string();
            let value = value
                .to_str()
                .map_err(|_| Response::bad_request("bad header value"))?
                .to_string();

            headers.insert(key, value);
        }

        let body = req
            .into_body()
            .collect()
            .await
            .map_err(|_| Response::bad_request("unable to get body"))?
            .to_bytes();

        let body = if body.is_empty() {
            None
        } else {
            let body = std::str::from_utf8(&body)
                .map_err(|_| Response::bad_request("unable to parse body"))?
                .to_string();

            Some(body)
        };

        Ok(ParsedRequest {
            method,
            version,
            path,
            query,
            headers,
            body,
        })
    }
}

// TODO: Can this be improved?
impl Debug for ParsedRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "\n----\n")?;
        writeln!(f, "> {} {} {}", self.method, self.path, self.version)?;

        if !&self.query.is_empty() {
            writeln!(f, "> query: {:?}", self.query)?;
        }

        for (key, value) in &self.headers {
            writeln!(f, "> {key}: {value}")?;
        }

        if let Some(body) = &self.body {
            write!(f, "\n{body}")?;
        }

        Ok(())
    }
}

pub(crate) enum Response {
    Error { status: StatusCode, message: String },
    Json { status: StatusCode, body: String },
}

impl Response {
    pub fn bad_request(message: impl Display) -> Self {
        Response::Error {
            status: StatusCode::BAD_REQUEST,
            message: message.to_string(),
        }
    }

    pub fn not_found(message: impl Display) -> Self {
        Response::Error {
            status: StatusCode::NOT_FOUND,
            message: message.to_string(),
        }
    }

    pub fn method_not_allowed(method: &Method) -> Self {
        Response::Error {
            status: StatusCode::METHOD_NOT_ALLOWED,
            message: format!("{method} not allowed"),
        }
    }

    pub fn json(status: StatusCode, body: impl serde::Serialize) -> Result<Self> {
        let body = serde_json::to_string(&body)?;
        Ok(Response::Json { status, body })
    }

    pub fn to_http(self) -> Result<HttpResponse> {
        let mut response = hyper::Response::builder();

        let (status, body) = match self {
            Response::Error { status, message } => {
                info!("{status}, {message}");
                (status, Bytes::from(message))
            }
            Response::Json { status, body } => {
                response = response.header(header::CONTENT_TYPE, HTTP_MIME_APPLICATION_JSON);

                trace!("{status}, {body}");
                (status, Bytes::from(body.clone()))
            }
        };

        let body = Full::new(body);
        let response = response.status(status).body(body)?;
        for (key, value) in response.headers() {
            trace!("{}: {}", key, value.to_str()?);
        }

        Ok(response)
    }
}
