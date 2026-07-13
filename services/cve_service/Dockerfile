# Собирается из корня монорепо: docker build -f services/cve_service/Dockerfile .
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /uvx /bin/

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY . /app
RUN uv sync --frozen --package cve-service --no-dev

EXPOSE 8000
# HTTP-фасад. Celery-воркер поднимается отдельным сервисом в compose (команда переопределяется).
CMD ["uv", "run", "--no-sync", "uvicorn", "cve_service.main:app", \
     "--host", "0.0.0.0", "--port", "8000"]
