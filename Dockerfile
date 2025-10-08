# Dockerfile - robust for Pillow / ReportLab builds
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install required OS packages for building Pillow / reportlab and for general apps
# - build-essential: compilers
# - libjpeg-dev, zlib1g-dev, libfreetype6-dev: common image libs used by Pillow
# - libssl-dev: SSL
# - libxml2-dev libxslt1-dev: sometimes used by XML libs
# - gcc, pkg-config for builds
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential \
      gcc \
      libjpeg-dev \
      zlib1g-dev \
      libfreetype6-dev \
      libssl-dev \
      libxml2-dev \
      libxslt1-dev \
      pkg-config \
      git \
      curl \
    && rm -rf /var/lib/apt/lists/*

# Copy only pip/requirement files first to leverage layer caching
COPY requirements.txt .

# Upgrade pip/setuptools/wheel before installing dependencies
RUN python -m pip install --upgrade pip setuptools wheel
# Install dependencies. Use no-cache-dir to reduce image size.
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

EXPOSE 5000

# Default command using gunicorn
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "2"]
