from typing import Any

import inject

from dw_auth.domain import AuthenticatedPrincipal, Principal
from dw_auth.ports import Authenticator
from dw_core.resolver import ResolutionContext


class PrincipalArgumentResolver:
    def supports(self, arg_type: Any) -> bool:
        return (
            isinstance(arg_type, type)
            and issubclass(arg_type, Principal)
        )

    def resolve(
        self,
        *,
        arg_name: str,
        arg_type: Any,
        context: ResolutionContext,
        resolved_kwargs: dict,
    ) -> dict:
        authenticator = inject.instance(Authenticator)
        principal = authenticator.authenticate(context.headers)

        if isinstance(arg_type, type) and issubclass(
            arg_type, AuthenticatedPrincipal
        ):
            if not isinstance(principal, AuthenticatedPrincipal):
                raise PermissionError('Unauthorized')

        return {arg_name: principal}
