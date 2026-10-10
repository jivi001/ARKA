//! Direct-IP Dialing Connector with Kernel Peer Verification.
//!
//! Enforces:
//! - Direct IP socket dialing to the pinned, pre-validated IP address
//! - Immediate post-connect peer address verification (`socket.peer_addr() == pinned_ip`)
//! - Strict rejection if OS socket connects to an unvalidated peer
//! - Configurable connection timeouts

use crate::errors::NetworkPolicyError;
use crate::validator::PinnedDestination;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct DirectIpConnector;

impl DirectIpConnector {
    /// Connects directly to the pinned IP address and verifies the connected socket peer.
    pub async fn connect(
        destination: &PinnedDestination,
        timeout_ms: u64,
    ) -> Result<TcpStream, NetworkPolicyError> {
        let socket_addr = destination.socket_addr();

        let dial_future = TcpStream::connect(socket_addr);
        let stream = match timeout(Duration::from_millis(timeout_ms), dial_future).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                return Err(NetworkPolicyError::ConnectionFailed(format!(
                    "TCP connect to {} failed: {}",
                    socket_addr, e
                )));
            }
            Err(_) => {
                return Err(NetworkPolicyError::Timeout(
                    socket_addr.to_string(),
                    timeout_ms,
                ));
            }
        };

        // Post-connect peer verification
        let actual_peer = stream
            .peer_addr()
            .map_err(|e| NetworkPolicyError::ConnectionFailed(e.to_string()))?;

        if actual_peer.ip() != destination.ip {
            return Err(NetworkPolicyError::PeerMismatch {
                expected: destination.ip.to_string(),
                actual: actual_peer.ip().to_string(),
            });
        }

        Ok(stream)
    }
}
