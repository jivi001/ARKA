"""
Kernel Bridge Client Typed Exceptions.
"""


class KernelBridgeError(Exception):
    """Base exception for all kernel bridge errors."""

    def __init__(self, message: str, code: str = "ERR_KERNEL_BRIDGE", retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class KernelAuthError(KernelBridgeError):
    """Raised when authentication token or peer UID validation fails."""

    pass


class KernelReplayError(KernelBridgeError):
    """Raised when the kernel detects a proposal nonce collision or replay."""

    pass


class KernelEmergencyStopError(KernelBridgeError):
    """Raised when a proposal is rejected due to active emergency stop."""

    pass


class KernelScopeError(KernelBridgeError):
    """Raised when the proposed target violates active mission scope."""

    pass
