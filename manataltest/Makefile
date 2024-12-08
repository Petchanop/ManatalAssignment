HOST=127.0.0.1
PORT=8000
APP=manataltest

run:
	uvicorn ${APP}.asgi:app --host ${HOST} --port ${PORT}

watch:
	uvicorn ${APP}.asgi:app --host ${HOST} --port ${PORT} --reload

migrations:
	python -m manage makemigrations

migrate:
	python -m manage migrate

generates-requirement:
	pip freeze > requirements.txt

install:
	pip install -r requirements.txt