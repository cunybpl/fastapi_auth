from .app import app
import base64
import json
from typing import Dict
from fastapi.testclient import TestClient
from fastapi_auth0 import Auth0User

client = TestClient(app)


def test_public():
    resp = client.get("/public")
    assert resp.status_code == 200, resp.text

    resp = client.get("/also-public")
    assert resp.status_code == 200, resp.text

    resp = client.get("/secure")
    assert resp.status_code == 403, resp.text

    resp = client.get("/also-secure")
    assert (
        resp.status_code == 403
    ), resp.text  # should be 401, see https://github.com/tiangolo/fastapi/pull/2120

    resp = client.get("/also-secure-2")
    assert (
        resp.status_code == 403
    ), resp.text  # should be 401, see https://github.com/tiangolo/fastapi/pull/2120

    resp = client.get("/secure-scoped")
    assert (
        resp.status_code == 403
    ), resp.text  # should be 401, see https://github.com/tiangolo/fastapi/pull/2120


def test_private(mocker):
    unverified_header = {"kid": "veryrealkid"}
    payload = {
        "sub": "whatsub",
        "permissions": ["crude"],
        # "email": "blah@yada.com",
        "scope": "read:scope1 read:scope2",
        "gty": "client-credentials",
        "org_id": "cia",
    }
    mocker.patch("jose.jwt.get_unverified_header", return_value=unverified_header)
    mocker.patch("jose.jwt.decode", return_value=payload)

    headers = {"Authorization": "Bearer adfdf"}
    resp = client.get("/secure", headers=headers)
    assert resp.status_code == 200, resp.text

    resp = client.get("/also-secure", headers=headers)
    assert resp.status_code == 200, resp.text

    resp2 = client.get("/also-secure-2", headers=headers)
    assert resp2.status_code == 200, resp2.text

    user = Auth0User(**resp.json())
    assert user.id == "whatsub"
    assert user.permissions == ["crude"]

    # M2M app is not subject to RBAC, so any permission given to it will also authorize the scope.
    resp = client.get("/secure-scoped", headers=headers)
    assert resp.status_code == 200, resp.text
