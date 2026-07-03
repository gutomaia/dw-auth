from typing import Mapping, Sequence

from dw_auth.domain import (
    AnonymousPrincipal,
    AuthenticatedPrincipal,
    Principal,
)
from dw_auth.ports import Authenticator


class CompositeAuthenticator(Authenticator):
    def __init__(self, authenticators: Sequence[Authenticator]):
        self._authenticators = list(authenticators)

    def authenticate(self, headers: Mapping[str, str] | None) -> Principal:
        for authenticator in self._authenticators:
            principal = authenticator.authenticate(headers)
            if isinstance(principal, AuthenticatedPrincipal):
                return principal
        return AnonymousPrincipal()
