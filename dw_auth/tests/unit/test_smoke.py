from dw_auth.domain import AuthenticatedPrincipal, Principal
from dw_auth.exceptions import Forbidden, Unauthorized
from dw_auth.tests.authenticator_spec import AuthenticatorSpec


def test_authenticated_principal_is_a_principal():
    principal = AuthenticatedPrincipal(subject='user-1')
    assert isinstance(principal, Principal)


def test_auth_exceptions_are_exceptions():
    assert issubclass(Unauthorized, Exception)
    assert issubclass(Forbidden, Exception)


class AuthenticatorSpecSmokeTest(AuthenticatorSpec):
    def given_configured_authenticator(self):
        from dw_auth.domain import AnonymousPrincipal

        class StaticAuthenticator:
            def authenticate(self, headers):
                if headers is None:
                    return AnonymousPrincipal()
                if headers.get('authorization') != 'good':
                    return AnonymousPrincipal()
                return AuthenticatedPrincipal(
                    subject='user-1',
                    provider='static',
                    claims={'role': 'user'},
                )

        self.authenticator = StaticAuthenticator()

    def given_headers(self, headers: dict[str, str] | None):
        self.headers = headers

    def given_headers_missing_credentials(self):
        self.headers = {}

    def given_headers_valid_credentials(self):
        self.headers = {'authorization': 'good'}

    def expected_authenticated_principal(self) -> tuple[str, str, dict]:
        return ('user-1', 'static', {'role': 'user'})

    def when_authenticate(self):
        self.principal = self.authenticator.authenticate(self.headers)

    def assert_anonymous_principal(self):
        from dw_auth.domain import AnonymousPrincipal

        assert isinstance(self.principal, AnonymousPrincipal)

    def assert_authenticated_principal(
        self,
        subject: str,
        provider: str,
        claims: dict | None = None,
    ):
        assert isinstance(self.principal, AuthenticatedPrincipal)
        assert self.principal.subject == subject
        assert self.principal.provider == provider
        if claims is not None:
            assert dict(self.principal.claims) == claims
