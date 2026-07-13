# Собирается из корня монорепо: docker build -f services/gateway/Dockerfile .
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /uvx /bin/

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Весь workspace нужен, т.к. gateway зависит от libs/common (workspace source).
COPY . /app
RUN uv sync --frozen --package gateway --no-dev

EXPOSE 8000
CMD ["uv", "run", "--no-sync", "uvicorn", "gateway.main:app", \
     "--host", "0.0.0.0", "--port", "8000"]
