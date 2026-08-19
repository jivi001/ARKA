import os
from abc import ABC, abstractmethod

from pydantic import SecretStr


class SecretsProvider(ABC):
    """Abstract base class for secrets providers."""

    @abstractmethod
    async def get_secret(self, key: str) -> SecretStr:
        """Get a secret by key.

        Args:
            key: The secret key.

        Returns:
            The secret value as a SecretStr.

        Raises:
            KeyError: If the secret is not found.
        """
        ...

    @abstractmethod
    async def has_secret(self, key: str) -> bool:
        """Check if a secret exists.

        Args:
            key: The secret key.

        Returns:
            True if the secret exists, False otherwise.
        """
        ...


class EnvironmentSecretsProvider(SecretsProvider):
    """Secrets provider that reads from environment variables."""

    async def get_secret(self, key: str) -> SecretStr:
        value = os.environ.get(key)
        if value is None:
            raise KeyError(f"Secret '{key}' not found in environment.")
        return SecretStr(value)

    async def has_secret(self, key: str) -> bool:
        return key in os.environ


class VaultSecretsProvider(SecretsProvider):
    """Secrets provider for HashiCorp Vault. Placeholder for Phase 2+."""

    def __init__(self, addr: str | None = None, token: SecretStr | None = None):
        self.addr = addr
        self.token = token

    async def get_secret(self, key: str) -> SecretStr:
        raise NotImplementedError("Vault secrets provider not implemented for Phase 1.")

    async def has_secret(self, key: str) -> bool:
        raise NotImplementedError("Vault secrets provider not implemented for Phase 1.")


def create_secrets_provider(backend: str) -> SecretsProvider:
    """Create a secrets provider instance based on the backend name.

    Args:
        backend: The backend name ('env' or 'vault').

    Returns:
        An instance of SecretsProvider.

    Raises:
        ValueError: If the backend is unsupported.
    """
    if backend == "env":
        return EnvironmentSecretsProvider()
    elif backend == "vault":
        return VaultSecretsProvider()
    else:
        raise ValueError(f"Unsupported secrets backend: {backend}")
