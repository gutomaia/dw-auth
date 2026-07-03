from dw_auth.composite import CompositeAuthenticator
from dw_auth.domain import AnonymousPrincipal, AuthenticatedPrincipal
from dw_auth.ports import Authenticator


class AlwaysAnonymous(Authenticator):
    def authenticate(self, headers):
        return AnonymousPrincipal()


class StaticAuthenticator(Authenticator):
    def __init__(self, header: str, subject: str, provider: str):
        self._header = header
        self._subject = subject
        self._provider = provider

    def authenticate(self, headers):
        if headers and self._header in headers:
            return AuthenticatedPrincipal(
                subject=self._subject, provider=self._provider
            )
        return AnonymousPrincipal()


def test_no_authenticators_returns_anonymous():
    authenticator = CompositeAuthenticator([])
    assert isinstance(authenticator.authenticate({}), AnonymousPrincipal)


def test_all_anonymous_returns_anonymous():
    authenticator = CompositeAuthenticator(
        [AlwaysAnonymous(), AlwaysAnonymous()]
    )
    assert isinstance(
        authenticator.authenticate({'authorization': 'x'}), AnonymousPrincipal
    )


def test_returns_first_authenticated_principal():
    authenticator = CompositeAuthenticator(
        [
            AlwaysAnonymous(),
            StaticAuthenticator('x-token', 'user-jwt', 'jwt'),
            StaticAuthenticator('x-api-key', 'user-key', 'apikey'),
        ]
    )

    principal = authenticator.authenticate({'x-token': 't', 'x-api-key': 'k'})

    assert isinstance(principal, AuthenticatedPrincipal)
    assert principal.subject == 'user-jwt'
    assert principal.provider == 'jwt'


def test_falls_through_to_later_authenticator():
    authenticator = CompositeAuthenticator(
        [
            StaticAuthenticator('x-token', 'user-jwt', 'jwt'),
            StaticAuthenticator('x-api-key', 'user-key', 'apikey'),
        ]
    )

    principal = authenticator.authenticate({'x-api-key': 'k'})

    assert isinstance(principal, AuthenticatedPrincipal)
    assert principal.subject == 'user-key'
    assert principal.provider == 'apikey'


def test_missing_headers_returns_anonymous():
    authenticator = CompositeAuthenticator(
        [StaticAuthenticator('x-token', 'user-jwt', 'jwt')]
    )
    assert isinstance(authenticator.authenticate(None), AnonymousPrincipal)
