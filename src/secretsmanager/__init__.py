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

from secretsmanager.interface import (
    # Core
    SecretProvider,
    SecretValue,
    RotationPolicy,
    RotationSchedule,
    # Exceptions (canonical names)
    SecretError,
    SecretNotFoundError,
    AccessDeniedError,
    BackendUnavailableError,
    # Backward-compatible aliases
    SecretAccessDeniedError,
    SecretBackendError,
)
from secretsmanager.cache import CachedSecretProvider
from secretsmanager.audit import AuditLogger, AuditRecord
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
    "SecretBackendError",       # alias
    # Components
    "CachedSecretProvider",
    "AuditLogger",
    "AuditRecord",
    "PolicyTranslator",
]
