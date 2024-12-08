from datetime import datetime, timedelta, timezone
from typing import Annotated
import bcrypt
from fastapi.security import OAuth2PasswordBearer
import jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Security, status

from authentication.constants.constants import ALGORITHM, SECRET_KEY
from authentication.schemas.authentication import LoginSchema, TokenData
from users.schemas.users import ResponseUserSchema, User
from users.models import Users

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token")

# Hash a password using bcrypt


def hash_password(password):
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password=pwd_bytes, salt=salt)
    return hashed_password

# Check if the provided password matches the stored password (hashed)


def verify_password(plain_password, hashed_password):
    password_byte_enc = plain_password.encode('utf-8')
    result = bcrypt.checkpw(password=password_byte_enc,
                            hashed_password=hashed_password.encode('utf-8'))
    return result


# def verify_password(plain_password, hashed_password):
#     pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
#     if pwd_context.verify(plain_password, hashed_password):
#         return True
#     else:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


async def get_user_by_email_or_username(payload: LoginSchema):
    if payload.username:
        user = await Users.objects.aget(username=payload.username)
    elif payload.email:
        user = await Users.objects.aget(email=payload.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND
        )
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token=Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.InvalidTokenError:
        raise credentials_exception
    user = await Users.objects.aget(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[ResponseUserSchema, Depends(get_current_user)],
):
    print(current_user)
    # if current_user.disabled:
    #     raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
