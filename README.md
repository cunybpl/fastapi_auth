# fastapi_auth0

Reusable fastapi auth0 components; adapted from [dorinclisu/fastapi-auth0](https://github.com/dorinclisu/fastapi-auth0/). Click [here](https://github.com/dorinclisu/fastapi-auth0/blob/master/README.md) for detailed readme.

The main difference with `dorinclisu/fastapi-auth0` is that jwks are initialized (or fetched) only when the fastapi's app gets started contrary to fetching jwks when instantiating `Auth0` class. This can help with not having to provide actual Auth0 environment variables suc as domain and audience in unittesting. We also provide optional checking of token claims against Auth0's org_id.
### Example
Simple usecase..
```python
# app.py
import os
from fastapi_auth0 import Auth0, Auth0User
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "")
AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE", "")
AUTH0_ORG_ID = os.environ.get("AUTH0_ORG_ID", "")

READ_SCOPE1 = "read:scope1"

SCOPES = {
    READ_SCOPE1: "read scope1",
}

auth0 = Auth0(
    domain=AUTH0_DOMAIN, api_audience=AUTH0_AUDIENCE, org_id=AUTH0_ORG_ID, scopes=SCOPES
)

#main
from fastapi import FastAPI, Depends, Security
from fastah
app = FastAPI()

@app.on_event("startup")
async def startup() -> None:
    auth0.initialize_jwks() # fetching jwks


@app.get("/secure", dependencies=[Depends(auth0.implicit_scheme)])
def get_secure(user: Auth0User = Security(auth0.get_user, scopes=['read:scope1'])):
    return {"message": f"{user}"}
```

Testing

```python
#conftest.py
# fake dependency injection
@pytest.fixture
def get_user():
    """override dep injector"""

    async def _get_user():
        return "blah"

    return _get_user

@pytest.fixture
def test_app(get_user):
    main.app.dependency_overrides[main.auth0.get_user] = get_user
    yield main.app
    main.app.dependency_overrides = {}

# fake user
@pytest.fixture(scope="module")
def get_user_with_auth():
    """override dep injector with a real boi"""

    async def _get_user():
        return fastapi_auth0.Auth0User(
            sub="user1",
            org_id="org1",
            permissions=None,
            email=None,
            org_metadata=None,
            app_metadata=None,
        )

    return _get_user

@pytest.fixture(scope="module")
def module_test_app_with_auth(get_user_with_auth):
    main.app.dependency_overrides[main.auth0.get_user] = get_user_with_auth
    yield main.app
    main.app.dependency_overrides = {}
```