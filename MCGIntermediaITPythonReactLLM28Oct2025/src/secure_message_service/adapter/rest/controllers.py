"""
REST controllers for SecureMessageService - initial implementation.

Implements:
- POST /messages : create message (validation + sanitization, returns queued)
- GET /messages/{id} : placeholder
- POST /process : placeholder

This implementation focuses on input validation and returning a stable response
so we can write unit tests without DB or Celery wiring yet.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from uuid import UUID, uuid4
from typing import Optional
import html
import re

router = APIRouter()
security = HTTPBearer(auto_error=False)


class CreateMessageRequest(BaseModel):
    user_id: UUID = Field(...)
    content: str = Field(..., max_length=5000)


class CreateMessageResponse(BaseModel):
    message_id: UUID
    status: str


def sanitize_content(content: str) -> str:
    # Basic sanitization: escape HTML and remove script-like patterns
    content = html.escape(content)
    patterns = [r'<script[^>]*>.*?</script>', r'javascript:', r'data:text/html', r'vbscript:', r'on\w+\s*=']
    for p in patterns:
        content = re.sub(p, '', content, flags=re.IGNORECASE | re.DOTALL)
    content = ' '.join(content.split())
    return content.strip()


def verify_jwt(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    # Minimal JWT verification placeholder used for role checking in tests
    if not credentials or not credentials.credentials:
        # Allow anonymous for now but raise 403 to indicate missing token
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Missing JWT')
    token = credentials.credentials
    # Very simple mock parsing: token format "sub:role" (for tests only)
    if ':' not in token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Invalid token')
    sub, role = token.split(':', 1)
    return {"sub": sub, "role": role}


@router.post('/messages', response_model=CreateMessageResponse, status_code=status.HTTP_201_CREATED)
async def create_message(req: CreateMessageRequest, jwt=Depends(verify_jwt)):
    # Only 'user' and 'admin' roles allowed
    if jwt.get('role') not in ['user', 'admin']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Forbidden')

    if not req.content or not req.content.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Content cannot be empty')

    if len(req.content) > 5000:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Content too long')

    sanitized = sanitize_content(req.content)
    if not sanitized:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Content invalid after sanitization')

    # Return queued status and generated id (persistence will be added later)
    return CreateMessageResponse(message_id=uuid4(), status='queued')


@router.get('/messages/{message_id}')
async def get_message(message_id: UUID, jwt=Depends(verify_jwt)):
    # Placeholder until persistence & decryption implemented
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail='Not implemented')


@router.post('/process')
async def process_message(message_id: UUID, jwt=Depends(verify_jwt)):
    # Placeholder until messaging & LLM implemented
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail='Not implemented')
