"""sanity_check must trust a target that gates on the token and flag one that does not."""

from jwtcheck.checks import sanity_check


class _Resp:
    def __init__(self, status):
        self.status_code = status


class _Config:
    user_path = "/me"


class FakeClient:
    """A client whose get() status for a token is decided by get_fn."""

    def __init__(self, get_fn):
        self.config = _Config()
        self._get_fn = get_fn

    def login(self):
        return "real-token", _Resp(200)

    def get(self, path, token):
        return _Resp(self._get_fn(token))


def test_sanity_passes_when_the_endpoint_gates_on_the_token():
    client = FakeClient(lambda token: 200 if token == "real-token" else 401)
    assert sanity_check(client) == (True, "ok")


def test_sanity_flags_an_endpoint_that_accepts_a_bogus_token():
    client = FakeClient(lambda token: 200)
    ok, reason = sanity_check(client)
    assert ok is False
    assert "bogus" in reason


def test_sanity_flags_when_a_valid_token_is_rejected():
    client = FakeClient(lambda token: 401)
    ok, reason = sanity_check(client)
    assert ok is False
    assert "valid token" in reason
