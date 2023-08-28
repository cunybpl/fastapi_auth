import json
import logging
import os
from typing import Optional, Dict, List, Any
import urllib.parse
import urllib.request

from jose import jwt  # type: ignore
from fastapi import HTTPException, Depends, Request
from fastapi.security import (
    SecurityScopes,
    HTTPBearer,
    HTTPAuthorizationCredentials,
    OAuth2,
    OAuth2PasswordBearer,
    OAuth2AuthorizationCodeBearer,
    OpenIdConnect,
)
from fastapi.openapi.models import OAuthFlows, OAuthFlowImplicit
import pydantic
from typing_extensions import TypedDict


logger = logging.getLogger("fastapi_auth0")

# auth0_rule_namespace: str = os.getenv(
#     "AUTH0_RULE_NAMESPACE", "https://github.com/dorinclisu/fastapi-auth0"
# )


class Auth0UnauthenticatedException(HTTPException):
    def __init__(self, detail: str, **kwargs: Dict[str, Any]):
        """Returns HTTP 401"""
        super().__init__(401, detail, **kwargs)


class Auth0UnauthorizedException(HTTPException):
    def __init__(self, detail: str, **kwargs: Dict[str, Any]):
        """Returns HTTP 403"""
        super().__init__(403, detail, **kwargs)


class HTTPAuth0Error(pydantic.BaseModel):
    detail: str


unauthenticated_response: Dict[int, Any] = {401: {"model": HTTPAuth0Error}}
unauthorized_response: Dict[int, Any] = {403: {"model": HTTPAuth0Error}}
security_responses: Dict[int, Any] = {
    **unauthenticated_response,
    **unauthorized_response,
}


class Auth0User(pydantic.BaseModel):
    id: str = pydantic.Field(..., alias="sub")
    permissions: Optional[List[str]] = None
    # email: Optional[str] = pydantic.Field(None, alias=f"{auth0_rule_namespace}/email")  # type: ignore [literal-required]
    email: Optional[
        str
    ] = None  # just leaving an empty field so that we don't have to modify the rest..
    org_id: Optional[str] = None
    org_metadata: Optional[Dict[str, Any]] = None
    app_metadata: Optional[Dict[str, Any]] = None


class Auth0HTTPBearer(HTTPBearer):
    async def __call__(
        self, request: Request
    ) -> Optional[HTTPAuthorizationCredentials]:
        return await super().__call__(request)


class OAuth2ImplicitBearer(OAuth2):
    def __init__(
        self,
        authorizationUrl: str,
        scopes: Dict[str, str] = {},
        scheme_name: Optional[str] = None,
        auto_error: bool = True,
    ):
        flows = OAuthFlows(
            implicit=OAuthFlowImplicit(authorizationUrl=authorizationUrl, scopes=scopes)
        )
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        # Overwrite parent call to prevent useless overhead, the actual auth is done in Auth0.get_user
        # This scheme is just for Swagger UI
        return None


class JwksKeyDict(TypedDict):
    kid: str
    kty: str
    use: str
    n: str
    e: str


class JwksDict(TypedDict):
    keys: List[JwksKeyDict]


class Auth0:
    def __init__(
        self,
        domain: str,
        api_audience: str,
        org_id: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
        scope_auto_error: bool = True,
        email_auto_error: bool = False,
    ):
        self.domain = domain
        self.audience = api_audience
        self.org_id = org_id
        self.scopes = scopes if scopes else {}

        self.scope_auto_error = scope_auto_error
        self.email_auto_error = email_auto_error

        # XXX
        # not necessarily needed here since we are not publishing this; we can always reverse later on if needed
        # self.auth0_user_model = auth0user_model

        authorization_url_qs = urllib.parse.urlencode({"audience": self.audience})
        authorization_url = f"https://{self.domain}/authorize?{authorization_url_qs}"
        self.implicit_scheme = OAuth2ImplicitBearer(
            authorizationUrl=authorization_url,
            scopes=self.scopes,
            scheme_name="Auth0ImplicitBearer",
        )
        self.password_scheme = OAuth2PasswordBearer(
            tokenUrl=f"https://{self.domain}/oauth/token", scopes=self.scopes
        )
        self.authcode_scheme = OAuth2AuthorizationCodeBearer(
            authorizationUrl=authorization_url,
            tokenUrl=f"https://{self.domain}/oauth/token",
            scopes=self.scopes,
        )
        self.oidc_scheme = OpenIdConnect(
            openIdConnectUrl=f"https://{self.domain}/.well-known/openid-configuration"
        )

    def initialize_jwks(self) -> None:
        self.algorithms = ["RS256"]
        r = urllib.request.urlopen(f"https://{self.domain}/.well-known/jwks.json")
        self.jwks: JwksDict = json.loads(r.read())

    async def get_user(
        self,
        security_scopes: SecurityScopes,
        creds: Optional[HTTPAuthorizationCredentials] = Depends(
            Auth0HTTPBearer(auto_error=False)
        ),
    ) -> Auth0User:
        """
        Verify the Authorization: Bearer token and return the user.
        If there is any problem and auto_error = True then raise Auth0UnauthenticatedException or Auth0UnauthorizedException,
        otherwise return None.

        Not to be called directly, but to be placed within a Depends() or Security() wrapper.
        Example: def path_op_func(user: Auth0User = Security(auth.get_user)).
        """
        if creds is None:
            # See HTTPBearer from FastAPI:
            # latest - https://github.com/tiangolo/fastapi/blob/master/fastapi/security/http.py
            # 0.65.1 - https://github.com/tiangolo/fastapi/blob/aece74982d7c9c1acac98e2c872c4cb885677fc7/fastapi/security/http.py
            # must be 403 until solving https://github.com/tiangolo/fastapi/pull/2120
            raise HTTPException(403, detail="Missing bearer token")
        token = creds.credentials
        payload: Dict[str, Any] = {}
        try:
            payload = self._decode_token(token)

            # payload checks
            self.check_for_grant_type(payload)
            self.check_for_org_id(payload)
            if self.scope_auto_error:
                self.check_for_scopes(security_scopes, payload)

            return self._parse_user_from_payload(payload)
        except jwt.ExpiredSignatureError:
            raise Auth0UnauthenticatedException(detail="Expired token")

        except jwt.JWTClaimsError:
            raise Auth0UnauthenticatedException(
                detail="Invalid token claims (wrong issuer or audience)"
            )

        except jwt.JWTError:
            raise Auth0UnauthenticatedException(detail="Malformed token")

        except Auth0UnauthenticatedException:
            raise

        except Auth0UnauthorizedException:
            raise

        except Exception as e:
            # This is an unlikely case but handle it just to be safe (maybe the token is specially crafted to bug our code)
            logger.error(f'Handled exception decoding token: "{e}"', exc_info=True)
            raise Auth0UnauthenticatedException(detail="Error decoding token")

    def _decode_token(self, token: str) -> Dict[str, Any]:
        unverified_header = jwt.get_unverified_header(token)

        if "kid" not in unverified_header:
            raise Auth0UnauthenticatedException(detail="Malformed token header")

        payload: Dict[str, Any] = {}  # shutup mypy
        rsa_key = {}
        for key in self.jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
                break
        if rsa_key:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=f"https://{self.domain}/",
            )
            return payload
        else:
            raise Auth0UnauthenticatedException(
                detail="Invalid kid header (wrong tenant or rotated public key)"
            )

    def _parse_user_from_payload(self, payload: Dict[str, Any]) -> Auth0User:
        try:
            user = Auth0User(**payload)

            if self.email_auto_error and not user.email:
                raise Auth0UnauthorizedException(
                    detail=f'Missing email claim (check auth0 rule "Add email to access token")'
                )

            return user

        except pydantic.ValidationError as e:
            logger.error(f'Handled exception parsing Auth0User: "{e}"', exc_info=True)
            raise Auth0UnauthorizedException(detail="Error parsing Auth0User")

    def check_for_org_id(self, payload: Dict[str, Any]) -> None:
        # each deployment has its own org_id
        if self.org_id:
            org_id = payload.get("org_id", None)
            if org_id and self.org_id != org_id:
                raise Auth0UnauthorizedException(detail='Token "org_id" does not match')

    # XXX may have to take care of implicit flow later on
    def check_for_grant_type(self, payload: Dict[str, Any]) -> None:
        gty = payload.get("gty", None)
        if gty and gty != "client-credentials":
            raise Auth0UnauthorizedException(
                detail='Token "gty" is not client_credentials'
            )

    def check_for_scopes(
        self, security_scopes: SecurityScopes, payload: Dict[str, Any]
    ) -> None:
        """check for scopes"""
        token_scope_str = payload.get("scope", "")
        if isinstance(token_scope_str, str):
            token_scopes = token_scope_str.split()

            for scope in security_scopes.scopes:
                if scope not in token_scopes:
                    raise Auth0UnauthorizedException(
                        detail=f'Missing "{scope}" scope',
                        headers={
                            "WWW-Authenticate": f'Bearer scope="{security_scopes.scope_str}"'
                        },
                    )
        else:
            # This is an unlikely case but handle it just to be safe (perhaps auth0 will change the scope format)
            raise Auth0UnauthorizedException(
                detail='Token "scope" field must be a string'
            )
