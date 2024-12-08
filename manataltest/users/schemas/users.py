from datetime import datetime
from enum import Enum
import re
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, SecretStr, field_validator, field_serializer
from passlib.context import CryptContext
from rich import print

from manataltest.utils.slug import slugify
from users.models import Users


class Roles(str, Enum):
    ADMIN = 'admin'
    USER = 'user'


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


def validate_password(v):
    # Ensure the password has at least 1 uppercase letter and 1 digit
    print("debug password", v.get_secret_value())
    if not re.search(r'[A-Z]', v.get_secret_value()):
        raise ValueError(
            "Password must contain at least one uppercase letter.")
    if not re.search(r'\d', v.get_secret_value()):
        raise ValueError("Password must contain at least one digit.")
    return v.get_secret_value()


def hash_password(password):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    # return hash_password(password)
    return pwd_context.hash(password)


class CreateUserSchema(BaseModel):
    username: str
    email: EmailStr
    role: Roles
    password: SecretStr = Field(..., min_length=8)

    class Config:
        model = Users

    validate_password = field_validator('password')(validate_password)
    # def validate_password(cls, v):
    #     # Ensure the password has at least 1 uppercase letter and 1 digit
    #     print("debug password", v.get_secret_value())
    #     if not re.search(r'[A-Z]', v.get_secret_value()):
    #         raise ValueError(
    #             "Password must contain at least one uppercase letter.")
    #     if not re.search(r'\d', v.get_secret_value()):
    #         raise ValueError("Password must contain at least one digit.")
    #     return v.get_secret_value()
    hash_password = field_serializer('password')(hash_password)
    # def hash_password(self, password):
    #     pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    #     # return hash_password(password)
    #     return pwd_context.hash(password)


class UpdateUserSchema(BaseModel):
    email: EmailStr | None
    role: Roles | None
    # password: SecretStr | None

    # validate_password = field_validator('password')(validate_password)


class ResponseUserSchema(BaseModel):
    username: str
    email: EmailStr
    role: str
    id: UUID
    created_at: datetime
    updated_at: datetime

    @field_serializer("id")
    def slug_id(self, id: UUID):
        return slugify(id)
