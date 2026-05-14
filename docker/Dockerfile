FROM python:3.11-slim

RUN apt-get update && apt-get install -y git
RUN rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code FIRST
COPY . .

# Then install the package in editable mode
RUN pip install -e .

RUN useradd -m gitcheck
USER gitcheck

ENTRYPOINT ["gitcheck"]

# ENTRYPOINT ["python", "/app/main.py"]  Can we add this??
