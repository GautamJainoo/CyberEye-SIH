FROM python:3.11-slim

# Prevent python from writing pyc files and buffering stdout/stderr
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    WMSA_BASE_DIR=/app

# Install system dependencies (git for repos, curl, build-essential, ca-certificates, tar)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    ca-certificates \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Install gitleaks and osv-scanner binaries
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then GL_ARCH="x64"; OSV_ARCH="amd64"; else GL_ARCH="arm64"; OSV_ARCH="arm64"; fi && \
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_${GL_ARCH}.tar.gz" | tar -xz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks || true && \
    curl -sSL "https://github.com/google/osv-scanner/releases/download/v1.7.0/osv-scanner_linux_${OSV_ARCH}" -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner || true

WORKDIR /app

# Copy dependency manifests first to leverage Docker layer caching
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Pre-clone target repository so static scans are immediately ready
RUN git clone --depth 1 https://github.com/koala73/worldmonitor.git /app/target || true

# Copy source code and files
COPY . .

# Install wmsa in editable mode
RUN pip install --no-cache-dir -e .

# Expose backend API port
EXPOSE 8000

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Start the FastAPI server on 0.0.0.0 so it is accessible from host machine
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
