FROM python:3.13-slim AS base

WORKDIR /app

# Security: Run as non-root user
RUN addgroup --system arka && adduser --system --group arka

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[dev]"

# Copy application code
COPY . .

# Install the application
RUN pip install --no-cache-dir -e .

# Switch to non-root user
USER arka

EXPOSE 8000

CMD ["uvicorn", "arka.app.api:app", "--host", "0.0.0.0", "--port", "8000"]
