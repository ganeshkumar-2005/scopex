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

# Pin stable Nuclei version. To bump: update version and SHA256 hash from release checksums file.
ARG NUCLEI_VERSION=3.2.9
ARG NUCLEI_SHA256=944dd1316fd57c035c1eba71633ed992b519528935e45a716d1d3cdffb6990f0

# Download and install ProjectDiscovery's Nuclei binary with checksum verification
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O nuclei.zip \
    && echo "${NUCLEI_SHA256}  nuclei.zip" | sha256sum -c - \
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
