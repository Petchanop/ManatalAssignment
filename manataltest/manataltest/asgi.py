"""
ASGI config for manataltest project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

from fastapi.security import OAuth2PasswordBearer
from rich import print
from fastapi import FastAPI
from django.conf import settings
import manataltest.settings as manataltest_settings
from starlette.middleware.cors import CORSMiddleware
from django.apps import apps
import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "manataltest.settings")
application = get_asgi_application()

try:
    settings.configure(default_settings=manataltest_settings, DEBUG=True)
except RuntimeError:  # Avoid: 'Settings already configured.'
    pass

apps.populate(settings.INSTALLED_APPS)

app = FastAPI(title='Manatal test integrate fast api with django', debug=True)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def init(app: FastAPI):
    from users.routes.routes import router as users_router
    from authentication.routes.routes import router as authen_router
    from manataltest.urls import api_router

    api_router.include_router(users_router)
    api_router.include_router(authen_router)
    app.include_router(api_router)

    if settings.MOUNT_DJANGO_APP:
        app.mount("/django", application)  # type:ignore


init(app)
