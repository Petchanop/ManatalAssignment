from typing import Optional, Union
from pydantic import BaseModel, EmailStr, SecretStr, field_validator, model_validator
import re
from users.models import Users
from rich import print


class LoginSchema(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: SecretStr

    class Config:
        model = Users

    @field_validator('password')
    def validate_password(cls, v):
        # Ensure the password has at least 1 uppercase letter and 1 digit
        if not re.search(r'[A-Z]', v.get_secret_value()):
            raise ValueError(
                "Password must contain at least one uppercase letter.")
        if not re.search(r'\d', v.get_secret_value()):
            raise ValueError("Password must contain at least one digit.")
        return v.get_secret_value()

    @model_validator(mode="before")
    def validate_login_input(self):
        if not self["username"] and not self["email"]:
            raise ValueError(
                "Username or Email required."
            )
        if not self["password"]:
            raise ValueError(
                "Password required."
            )
        return self


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None
    scopes: list[str] = []


class LoginResponseSchema(BaseModel):
    username: str
    email: str
    token: Token
