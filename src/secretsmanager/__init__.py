"""Multi-cloud secrets manager with unified provider interface.

Public API::

    from secretsmanager import (
        SecretProvider,
        SecretValue,
        SecretNotFoundError,
        AccessDeniedError,
        BackendUnavailableError,
        CachedSecretProvider,
        AuditLogger,
        PolicyTranslator,
    )
"""

from secretsmanager.audit import AuditLogger, AuditRecord
from secretsmanager.cache import CachedSecretProvider
from secretsmanager.interface import (
    AccessDeniedError,
    BackendUnavailableError,
    RotationPolicy,
    RotationSchedule,
    # Backward-compatible aliases
    SecretAccessDeniedError,
    SecretBackendError,
    # Exceptions (canonical names)
    SecretError,
    SecretNotFoundError,
    # Core
    SecretProvider,
    SecretValue,
)
from secretsmanager.policy import PolicyTranslator

__all__ = [
    # Interface
    "SecretProvider",
    "SecretValue",
    "RotationPolicy",
    "RotationSchedule",
    # Exceptions
    "SecretError",
    "SecretNotFoundError",
    "AccessDeniedError",
    "BackendUnavailableError",
    "SecretAccessDeniedError",  # alias
    "SecretBackendError",  # alias
    # Components
    "CachedSecretProvider",
    "AuditLogger",
    "AuditRecord",
    "PolicyTranslator",
]
