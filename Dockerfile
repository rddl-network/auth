FROM --platform=linux/amd64 python:3.10-slim AS base
FROM base AS builder

RUN apt-get update && apt-get -y upgrade
RUN pip install --upgrade pip
RUN pip install poetry

WORKDIR /usr/src/app
COPY ./auth /usr/src/app/auth
COPY ./poetry.lock /usr/src/app/poetry.lock
COPY ./pyproject.toml /usr/src/app/pyproject.toml
COPY ./redis.conf /usr/src/app/redis.conf

RUN poetry config virtualenvs.create false
RUN poetry install --no-root

EXPOSE 8000:8000

RUN adduser --system --group nonroot
USER nonroot

CMD ["uvicorn", "auth.main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-keep-alive", "240", "--log-level=debug"]
