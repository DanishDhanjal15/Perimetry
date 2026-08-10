# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set metadata
LABEL maintainer="Jason13"
LABEL description="Perimetry - Information Gathering & Reconnaissance Toolkit"
LABEL version="2.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Create non-root user for security
RUN groupadd -r perimetry && useradd -r -g perimetry perimetry

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    git \
    curl \
    wget \
    nmap \
    whois \
    dnsutils \
    net-tools \
    iputils-ping \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/results /app/logs /app/config

# Set proper permissions
RUN chown -R perimetry:perimetry /app && \
    chmod -R 755 /app

# Switch to non-root user
USER perimetry

# Create volume for results and config
VOLUME ["/app/results", "/app/config"]

# Expose port (if needed for web interface in future)
EXPOSE 8080

# Set default command
ENTRYPOINT ["python", "-m", "perimetry"]

# Default command (can be overridden)
CMD ["--help"]
