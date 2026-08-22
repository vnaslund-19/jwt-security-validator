"""Talk to a target: log in, then call protected endpoints with a token."""

import requests


class Client:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()

    def login(self):
        cfg = self.config
        resp = self.session.post(cfg.base_url + cfg.login_path, json=cfg.credentials)
        return self._extract_token(resp), resp

    def get(self, path, token):
        cfg = self.config
        send = cfg.send_token
        if send["via"] == "header":
            headers = {send["name"]: send.get("prefix", "") + token}
            return self.session.get(cfg.base_url + path, headers=headers)
        if send["via"] == "cookie":
            self.session.cookies.clear()
            self.session.cookies.set(send["name"], token)
            return self.session.get(cfg.base_url + path)
        raise ValueError(f"unknown token transport: {send['via']}")

    def _extract_token(self, resp):
        src = self.config.token_from
        if src["source"] == "json":
            return resp.json().get(src["field"])
        if src["source"] == "cookie":
            return resp.cookies.get(src["name"])
        raise ValueError(f"unknown token source: {src['source']}")


def to_evidence(resp):
    """Turn a response into the request/response pair that proves a verdict."""
    req = resp.request
    return {
        "request": {
            "method": req.method,
            "url": req.url,
            "headers": dict(req.headers),
            "body": req.body,
        },
        "response": {
            "status": resp.status_code,
            "body": resp.text,
        },
    }
