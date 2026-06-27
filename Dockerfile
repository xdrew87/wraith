FROM python:3.12-slim

LABEL org.opencontainers.image.title="WRAITH"
LABEL org.opencontainers.image.description="Credential Exposure Monitor"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install dependencies first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ ./src/
COPY dashboard/ ./dashboard/
COPY config.yaml .

# Create required directories
RUN mkdir -p logs outputs

# Non-root user for security
RUN useradd -m -u 1001 wraith && chown -R wraith:wraith /app
USER wraith

EXPOSE 5050

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5050/api/v1/health')" || exit 1

CMD ["python", "src/main.py", "dashboard", "--host", "0.0.0.0", "--port", "5050"]
