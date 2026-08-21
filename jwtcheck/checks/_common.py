"""Small helpers shared by the checks."""


def login_token(client):
    token, _ = client.login()
    if not token:
        raise RuntimeError("login did not return a token")
    return token


def is_accepted(resp):
    return 200 <= resp.status_code < 300
