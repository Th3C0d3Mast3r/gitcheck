FROM python:3.11-slim

RUN apt-get update && apt-get install -y git
RUN rm -rf /var/lib/apt/lists/*  # this cleans up the apt cache to reduce the image size!

WORKDIR /app
COPY pyproject.toml .

RUN pip install -e .

COPY . .

RUN useradd -m gitcheck
USER gitcheck

ENTRYPOINT ["gitcheck"]

# ENTRYPOINT ["python", "/app/main.py"]  Can we add this??