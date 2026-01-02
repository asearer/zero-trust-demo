from typing import Optional
from pydantic import BaseModel, Field

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    mfa_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")
    device: Optional[str] = "unknown"

class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)
    device: Optional[str] = "unknown"

class LogoutRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)

class ResourceAccessRequest(BaseModel):
    action: str = Field(..., pattern=r"^(read|write|delete)$")
    resource: str = Field(..., min_length=1)
