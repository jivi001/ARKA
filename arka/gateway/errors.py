"""ARKA LLM Gateway Client Exceptions."""

class GatewayClientError(Exception):
    """Base exception for all LLM Gateway client errors."""

    def __init__(self, message: str, code: str = "ERR_GATEWAY", retryable: bool = False):
        super().__init__(f"[{code}] {message}")
        self.message = message
        self.code = code
        self.retryable = retryable


class GatewayTimeoutError(GatewayClientError):
    """Raised when an inference request times out."""

    def __init__(self, message: str = "Inference request timed out."):
        super().__init__(message, code="ERR_GATEWAY_TIMEOUT", retryable=True)


class GatewayDlpError(GatewayClientError):
    """Raised when a request is blocked by Data Loss Prevention policy."""

    def __init__(self, message: str):
        super().__init__(message, code="ERR_DLP_VIOLATION", retryable=False)


class GatewayPeerAuthError(GatewayClientError):
    """Raised when peer credential verification fails at the OS UDS layer."""

    def __init__(self, message: str):
        super().__init__(message, code="ERR_PEER_AUTH_FAILED", retryable=False)


class GatewayPayloadError(GatewayClientError):
    """Raised when request payload violates framing or strict JSON requirements."""

    def __init__(self, message: str, code: str = "ERR_INVALID_PAYLOAD"):
        super().__init__(message, code=code, retryable=False)
