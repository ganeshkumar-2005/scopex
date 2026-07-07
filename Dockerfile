# Use official Python slim image as the base
FROM python:3.11-slim-bookworm

# Set shell and non-interactive frontend
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-c"]

# Install system dependencies (nmap, curl, wget, unzip)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and install ProjectDiscovery's Nuclei binary
RUN LATEST_NUCLEI_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
    | grep -oP '"browser_download_url":\s*"\Khttps://[^"]+linux_amd64\.zip') \
    && wget -q "$LATEST_NUCLEI_URL" -O nuclei.zip \
    && unzip nuclei.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei.zip

# Create working directory
WORKDIR /app

# Copy python setup configuration first to leverage Docker build cache
COPY pyproject.toml README.md /app/

# Copy project files
COPY core/ /app/core/
COPY scanners/ /app/scanners/
COPY plugins/ /app/plugins/
COPY reports/ /app/reports/
COPY utils/ /app/utils/
COPY scopex.py /app/scopex.py
COPY config.json /app/config.json

# Install dependencies and package ScopeX in editable mode
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

# Create outputs volume
VOLUME /app/output

# Define entrypoint to directly call scopex CLI
ENTRYPOINT ["scopex"]
CMD ["--help"]
