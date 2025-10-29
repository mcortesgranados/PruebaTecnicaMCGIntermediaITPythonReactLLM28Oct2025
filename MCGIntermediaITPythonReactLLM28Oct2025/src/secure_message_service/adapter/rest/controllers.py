"""
REST controllers for SecureMessageService - initial implementation.

Implements:
- POST /messages : create message (validation + sanitization, returns queued)
- GET /messages/{id} : implemented (decrypt + RBAC using mock JWT)
- POST /process : placeholder

This implementation focuses on input validation and returning a stable response
so we can write unit tests without DB or Celery wiring yet.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from uuid import UUID, uuid4
from typing import Optional, Dict, Any
import html
import re
import datetime

# Import encryption utilities
from src.secure_message_service.adapter.persistence.encryption import (
    AESEncryptionService,
    load_encryption_key_from_env,
)

router = APIRouter()
security = HTTPBearer(auto_error=False)


class CreateMessageRequest(BaseModel):
    user_id: UUID = Field(...)
    content: str = Field(..., max_length=5000)


class CreateMessageResponse(BaseModel):
    message_id: UUID
    status: str


class GetMessageResponse(BaseModel):
    message_id: UUID
    content: str
    status: str
    created_at: datetime.datetime
    processed_at: Optional[datetime.datetime] = None


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


# Simple in-memory message store for incremental development.
# Schema: { UUID: { 'message_id': UUID, 'user_id': UUID, 'encrypted_content': str, 'status': str, 'created_at': datetime, 'processed_at': Optional[datetime] } }
MESSAGE_STORE: Dict[UUID, Dict[str, Any]] = {}

# Initialize encryption service. Prefer env var; fall back to a deterministic dev key if unset.
try:
    _KEY = load_encryption_key_from_env('ENCRYPTION_KEY')
except EnvironmentError:
    # Development fallback key (NOT for production)
    _KEY = b"\x00" * 32

_encryption_svc = AESEncryptionService(_KEY)


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

    # Persist the message to the in-memory store (encrypt before storing)
    message_id = uuid4()
    created_at = datetime.datetime.utcnow()
    encrypted = _encryption_svc.encrypt(sanitized)
    MESSAGE_STORE[message_id] = {
        'message_id': message_id,
        'user_id': req.user_id,
        'encrypted_content': encrypted,
        'status': 'queued',
        'created_at': created_at,
        'processed_at': None,
    }

    return CreateMessageResponse(message_id=message_id, status='queued')


@router.get('/messages/{message_id}', response_model=GetMessageResponse)
async def get_message(message_id: UUID, jwt=Depends(verify_jwt)):
    # Retrieve stored message
    record = MESSAGE_STORE.get(message_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Message not found')

    # RBAC: allow if admin or owner (jwt.sub matches stored user_id)
    role = jwt.get('role')
    sub = jwt.get('sub')
    owner_id = str(record['user_id']) if record.get('user_id') is not None else None
    if role != 'admin' and sub != owner_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Forbidden')

    # Decrypt content
    try:
        plaintext = _encryption_svc.decrypt(record['encrypted_content'])
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Decryption failed')

    return GetMessageResponse(
        message_id=record['message_id'],
        content=plaintext,
        status=record['status'],
        created_at=record['created_at'],
        processed_at=record['processed_at'],
    )


@router.post('/process')
async def process_message(message_id: UUID, jwt=Depends(verify_jwt)):
    # Placeholder until messaging & LLM implemented
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail='Not implemented')
