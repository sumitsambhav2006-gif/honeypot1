FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    default-libmysqlclient-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency manifest
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy platform source
COPY . .

# Expose Web SOC Dashboard port
EXPOSE 5000

ENV FLASK_ENV=production
ENV HOST=0.0.0.0
ENV PORT=5000

# Default command: launch web platform + collector
CMD ["python", "run.py", "all"]

