import json

from lib.lattice import Lattice


class DummyResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.content = json.dumps(payload).encode()
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def test_authenticate_stores_token_credentials_and_header():
    client = Lattice()
    client._raw_request = lambda *args, **kwargs: DummyResponse(
        200,
        {"status": "success", "token": "initial-token"}
    )

    assert client.authenticate("mcp-user", "api-key") is True
    assert client.auth_token == "initial-token"
    assert client._auth_credentials == ("mcp-user", "api-key")
    assert client.session.headers["Authorization"] == "Bearer initial-token"


def test_request_refreshes_token_once_after_unauthorized_response():
    client = Lattice()
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, dict(client.session.headers)))
        if url.endswith("/auth"):
            token = "initial-token" if len(calls) == 1 else "refreshed-token"
            return DummyResponse(200, {"status": "success", "token": token})
        if len([call for call in calls if call[1].endswith("/imports")]) == 1:
            return DummyResponse(401, {"status": "error", "message": "Invalid token"})
        return DummyResponse(200, {"status": "success", "imports": []})

    client._raw_request = fake_request

    assert client.authenticate("mcp-user", "api-key") is True
    assert client.get_imports() == {"status": "success", "imports": []}
    assert client.auth_token == "refreshed-token"
    assert client.session.headers["Authorization"] == "Bearer refreshed-token"
    assert [method for method, _, _ in calls] == ["POST", "GET", "POST", "GET"]


def test_request_does_not_retry_unauthorized_without_credentials():
    client = Lattice()
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url))
        return DummyResponse(401, {"status": "error", "message": "Invalid token"})

    client._raw_request = fake_request

    assert client.get_imports() == {"status": "error", "message": "Failed to get imports"}
    assert len(calls) == 1
