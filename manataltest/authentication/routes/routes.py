from datetime import timedelta
import os
from typing import Annotated
from django.db import IntegrityError
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from authentication.constants.constants import ACCESS_TOKEN_EXPIRE_MINUTES
from authentication.schemas.authentication import LoginSchema, Token
from authentication.utils.authentication import create_access_token, get_user_by_email_or_username, verify_password
from users.models import Users
from users.schemas.users import CreateUserSchema, ResponseUserSchema
from rich import print

router = APIRouter(tags=["Authentication"])


@router.post("/register/", response_model=ResponseUserSchema, status_code=status.HTTP_201_CREATED)
async def register(user: CreateUserSchema):
    try:
        response = await Users.objects.acreate(**user.model_dump())
        return response
    except IntegrityError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    except Exception:
        raise HTTPException(status_cdoe=status.HTTP_500_INTERNAL_SERVER_ERROR)


@router.post("/login/", response_model=Token, status_code=status.HTTP_200_OK)
async def login(payload: LoginSchema):
    try:
        user = await get_user_by_email_or_username(payload)
        if verify_password(payload.password, user.password):
            access_token_expires = timedelta(
                minutes=float(ACCESS_TOKEN_EXPIRE_MINUTES)
            )
            access_token = create_access_token(
                data={"sub": user.username}, expires_delta=access_token_expires
            )
            return Token(access_token=access_token, token_type="bearer")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


@router.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = await get_user_by_email_or_username(form_data)
    if verify_password(form_data.password, user.password):
        access_token_expires = timedelta(
            minutes=float(ACCESS_TOKEN_EXPIRE_MINUTES))
        access_token = create_access_token(
            data={"sub": user.username},
            expires_delta=access_token_expires
        )
    return Token(access_token=access_token, token_type="bearer")
