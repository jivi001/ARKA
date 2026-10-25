//! HTTP transport abstraction for LLM Gateway Adapters.
//!
//! Provides a testable, secure boundary for outbound provider requests,
//! supporting mock responses, wire recording, status code handling,
//! and Direct-IP connection validation.

use crate::errors::GatewayError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn ok_json(body_str: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        Self {
            status: 200,
            headers,
            body: body_str.as_bytes().to_vec(),
        }
    }

    pub fn error(status: u16, body_str: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        Self {
            status,
            headers,
            body: body_str.as_bytes().to_vec(),
        }
    }
}

#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, GatewayError>;
}

/// Recorded outbound request for test inspection and verification.
#[derive(Debug, Clone)]
pub struct RecordedHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Deterministic mock HTTP transport for offline testing and wire-format verification.
#[derive(Default, Clone)]
pub struct MockHttpTransport {
    canned_responses: Arc<Mutex<Vec<(String, HttpResponse)>>>,
    recorded_requests: Arc<Mutex<Vec<RecordedHttpRequest>>>,
    default_response: Arc<Mutex<Option<HttpResponse>>>,
    forced_error: Arc<Mutex<Option<GatewayError>>>,
}

impl MockHttpTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_response(self, url_fragment: impl Into<String>, response: HttpResponse) -> Self {
        let mut list = self.canned_responses.lock().unwrap();
        list.push((url_fragment.into(), response));
        drop(list);
        self
    }

    pub fn with_default_response(self, response: HttpResponse) -> Self {
        let mut def = self.default_response.lock().unwrap();
        *def = Some(response);
        drop(def);
        self
    }

    pub fn with_forced_error(self, err: GatewayError) -> Self {
        let mut f = self.forced_error.lock().unwrap();
        *f = Some(err);
        drop(f);
        self
    }

    pub fn recorded_requests(&self) -> Vec<RecordedHttpRequest> {
        self.recorded_requests.lock().unwrap().clone()
    }

    pub fn clear_records(&self) {
        self.recorded_requests.lock().unwrap().clear();
    }
}

#[async_trait]
impl HttpTransport for MockHttpTransport {
    async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, GatewayError> {
        // Record request
        let recorded = RecordedHttpRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_vec(),
        };
        self.recorded_requests.lock().unwrap().push(recorded);

        // Check forced error
        if let Some(err) = self.forced_error.lock().unwrap().clone() {
            return Err(err);
        }

        // Find canned response matching URL fragment
        let canned = self.canned_responses.lock().unwrap();
        for (pattern, resp) in canned.iter() {
            if url.contains(pattern) {
                return Ok(resp.clone());
            }
        }
        drop(canned);

        // Fallback to default response
        if let Some(resp) = self.default_response.lock().unwrap().clone() {
            return Ok(resp);
        }

        // Fail closed if no mock configured
        Err(GatewayError::ProviderUnavailable(format!(
            "MockHttpTransport: No response configured for {} {}",
            method, url
        )))
    }
}
