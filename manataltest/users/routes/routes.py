from typing import Annotated, List
from django.db import IntegrityError, InternalError, OperationalError
from django.core.exceptions import ObjectDoesNotExist
from fastapi import APIRouter, Depends, HTTPException, status
from authentication.utils.authentication import get_current_user
from manataltest.utils.slug import slugify
from users.models import Users
from users.schemas.users import CreateUserSchema, ResponseUserSchema, UpdateUserSchema, User
from rich import print

# Create your views here.
router = APIRouter(tags=["Users"])


@router.post("/user/", response_model=ResponseUserSchema, status_code=status.HTTP_201_CREATED)
async def create_user(user: CreateUserSchema):
    try:
        response = await Users.objects.acreate(**user.model_dump())
        return response
    except IntegrityError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    except Exception:
        raise HTTPException(status_cdoe=status.HTTP_500_INTERNAL_SERVER_ERROR)


@router.get("/users/", response_model=List[ResponseUserSchema], status_code=status.HTTP_200_OK)
async def get_all_users():
    try:
        return [user async for user in Users.objects.all()]
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    except (InternalError, OperationalError):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except ObjectDoesNotExist:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


@router.get("/users/{user_id}", response_model=ResponseUserSchema, status_code=status.HTTP_200_OK)
async def get_user_by_id(user_id: str):
    try:
        if user_id:
            user_id = slugify(user_id, decode=True)
        user = await Users.objects.aget(id=user_id)
        return user
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
    except (InternalError, OperationalError):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except ObjectDoesNotExist:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


@router.get("/users/me/", response_model=ResponseUserSchema, status_code=status.HTTP_200_OK)
async def read_users_me(
    current_user: Annotated[ResponseUserSchema, Depends(get_current_user)],
):
    return current_user


@router.patch("/users/me/", response_model=ResponseUserSchema, status_code=status.HTTP_200_OK)
async def update_user(payload: UpdateUserSchema, current_user: Annotated[ResponseUserSchema, Depends(get_current_user)]):
    [setattr(current_user, key, value) for key, value in payload]
    await current_user.asave()
    return current_user
