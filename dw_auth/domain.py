from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class Principal:
    pass


@dataclass(frozen=True)
class AnonymousPrincipal(Principal):
    pass


@dataclass(frozen=True)
class AuthenticatedPrincipal(Principal):
    subject: str
    provider: str = 'unknown'
    claims: Mapping[str, Any] = field(default_factory=dict)
