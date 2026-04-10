class AuthenticatorSpec:
    def given_configured_authenticator(self):
        raise NotImplementedError()

    def given_headers(self, headers: dict[str, str] | None):
        raise NotImplementedError()

    def given_headers_missing_credentials(self):
        raise NotImplementedError()

    def given_headers_valid_credentials(self):
        raise NotImplementedError()

    def expected_authenticated_principal(self) -> tuple[str, str, dict]:
        raise NotImplementedError()

    def when_authenticate(self):
        raise NotImplementedError()

    def assert_anonymous_principal(self):
        raise NotImplementedError()

    def assert_authenticated_principal(
        self,
        subject: str,
        provider: str,
        claims: dict | None = None,
    ):
        raise NotImplementedError()

    def test_missing_headers_returns_anonymous_principal(self):
        self.given_configured_authenticator()
        self.given_headers(None)

        self.when_authenticate()

        self.assert_anonymous_principal()

    def test_missing_credentials_returns_anonymous_principal(self):
        self.given_configured_authenticator()
        self.given_headers_missing_credentials()

        self.when_authenticate()

        self.assert_anonymous_principal()

    def test_valid_credentials_returns_authenticated_principal(self):
        self.given_configured_authenticator()
        self.given_headers_valid_credentials()

        self.when_authenticate()

        subject, provider, claims = self.expected_authenticated_principal()
        self.assert_authenticated_principal(
            subject=subject,
            provider=provider,
            claims=claims,
        )
