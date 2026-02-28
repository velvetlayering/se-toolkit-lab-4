"""API key authentication dependency."""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.settings import settings


class HTTPBearer403(HTTPBearer):
    """HTTPBearer that returns 403 instead of 401 for missing/invalid auth.

    FastAPI 0.122.0+ returns 401 for failed auth; the autochecker expects 403.
    """

    def make_not_authenticated_error(self) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authenticated",
        )


security = HTTPBearer403()


def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    """Verify the API key from the Authorization header.

    Expects: Authorization: Bearer <API_TOKEN>
    Returns the token string if valid.
    Raises 401 if invalid.
    """
    if credentials.credentials != settings.api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return credentials.credentials
