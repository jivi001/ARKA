//! ARKA Worker-Broker Protocol
//!
//! Strongly-typed, versioned, bounded IPC protocol for communication between
//! the Execution Broker and isolated Worker sandboxes.

#![forbid(unsafe_code)]

pub mod codec;
pub mod errors;
pub mod messages;

pub use codec::ProtocolCodec;
pub use errors::ProtocolError;
pub use messages::{
    BrokerHandshakeResponse, CancelTaskRequest, ExecuteTaskRequest, ExecuteTaskResponse, Heartbeat,
    TaskExitStatus, WorkerHello, WorkerMessage, MAX_MESSAGE_BYTES, MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES, PROTOCOL_VERSION,
};

#[cfg(test)]
mod tests {
    use super::*;
    use arka_core_types::id::{ActionId, CapabilityId, ExecutionId, MissionId, WorkerId};

    #[test]
    fn test_worker_hello_roundtrip() {
        let hello = WorkerHello {
            protocol_version: PROTOCOL_VERSION,
            worker_id: WorkerId::new("wrk-01").unwrap(),
            execution_id: ExecutionId::new("exc-100").unwrap(),
            mission_id: MissionId::new("mis-alpha").unwrap(),
            capability_id: CapabilityId::new("TCP_CONNECT").unwrap(),
            nonce: "test-nonce-123".to_string(),
        };
        let msg = WorkerMessage::WorkerHello(hello.clone());

        let encoded = ProtocolCodec::encode(&msg).expect("Failed to encode");
        let decoded = ProtocolCodec::decode(&encoded).expect("Failed to decode");

        match decoded {
            WorkerMessage::WorkerHello(decoded_hello) => {
                assert_eq!(decoded_hello, hello);
            }
            _ => panic!("Unexpected decoded message variant"),
        }
    }

    #[test]
    fn test_execute_task_roundtrip() {
        let task = ExecuteTaskRequest {
            execution_id: ExecutionId::new("exc-101").unwrap(),
            action_id: ActionId::new("act-500").unwrap(),
            action_hash: "a".repeat(64),
            capability_id: CapabilityId::new("TCP_CONNECT").unwrap(),
            target: serde_json::json!({"ip": "127.0.0.1", "port": 8080}),
            parameters: serde_json::json!({"timeout_ms": 1000}),
            deadline_unix_ms: 1800000000,
        };
        let msg = WorkerMessage::ExecuteTask(task.clone());

        let encoded = ProtocolCodec::encode(&msg).expect("Failed to encode");
        let decoded = ProtocolCodec::decode(&encoded).expect("Failed to decode");

        match decoded {
            WorkerMessage::ExecuteTask(decoded_task) => {
                assert_eq!(decoded_task, task);
            }
            _ => panic!("Unexpected decoded message variant"),
        }
    }

    #[test]
    fn test_task_response_roundtrip() {
        let response = ExecuteTaskResponse {
            execution_id: ExecutionId::new("exc-101").unwrap(),
            action_id: ActionId::new("act-500").unwrap(),
            action_hash: "a".repeat(64),
            status: TaskExitStatus::Success,
            exit_code: Some(0),
            stdout_truncated: Some("Connection established".to_string()),
            stderr_truncated: None,
            structured_output: serde_json::json!({"connected": true, "rtt_ms": 12}),
            evidence_hashes: vec!["evidence-hash-1".to_string()],
            completed_at_unix_ms: 1790000000,
        };
        let msg = WorkerMessage::TaskResponse(response.clone());

        let encoded = ProtocolCodec::encode(&msg).expect("Failed to encode");
        let decoded = ProtocolCodec::decode(&encoded).expect("Failed to decode");

        match decoded {
            WorkerMessage::TaskResponse(decoded_resp) => {
                assert_eq!(decoded_resp, response);
            }
            _ => panic!("Unexpected decoded message variant"),
        }
    }

    #[test]
    fn test_unknown_field_rejected() {
        let bad_json = r#"{
            "type": "worker_hello",
            "payload": {
                "protocol_version": 1,
                "worker_id": "wrk-01",
                "execution_id": "exc-100",
                "mission_id": "mis-alpha",
                "capability_id": "TCP_CONNECT",
                "nonce": "test-nonce-123",
                "injected_extra_field": "exploit"
            }
        }"#;

        let result = ProtocolCodec::decode(bad_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_oversized_message_rejected() {
        let huge_padding = "x".repeat(MAX_MESSAGE_BYTES + 10);
        let bad_json = format!(
            r#"{{
            "type": "cancel_task",
            "payload": {{
                "execution_id": "exc-100",
                "reason": "{}"
            }}
        }}"#,
            huge_padding
        );

        let result = ProtocolCodec::decode(&bad_json);
        assert!(matches!(
            result,
            Err(ProtocolError::OversizedMessage { .. })
        ));
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let bad_version_json = r#"{
            "type": "worker_hello",
            "payload": {
                "protocol_version": 999,
                "worker_id": "wrk-01",
                "execution_id": "exc-100",
                "mission_id": "mis-alpha",
                "capability_id": "TCP_CONNECT",
                "nonce": "test-nonce-123"
            }
        }"#;

        let result = ProtocolCodec::decode(bad_version_json);
        assert!(matches!(
            result,
            Err(ProtocolError::UnsupportedProtocolVersion { version: 999, .. })
        ));
    }
}
