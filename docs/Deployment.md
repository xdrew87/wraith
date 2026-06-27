# WRAITH — Deployment Guide

## Local Development

```bash
py src/main.py dashboard --port 5050
```

Binds to `127.0.0.1:5050` by default. Access at `http://localhost:5050`.

---

## Production Docker Deployment

### 1. Configure environment

```bash
cp .env.example .env
# Fill in API keys and alert credentials
```

### 2. Start the service

```bash
docker compose up -d
```

### 3. Health check

```bash
curl http://localhost:5050/api/v1/health
```

### 4. View logs

```bash
docker compose logs -f wraith
```

### 5. Run CLI commands inside the container

```bash
docker compose exec wraith python src/main.py watch example.com
docker compose exec wraith python src/main.py monitor
```

---

## Nginx Reverse Proxy

To expose the dashboard via a domain with TLS:

```nginx
server {
    listen 443 ssl;
    server_name wraith.internal.example.com;

    ssl_certificate     /etc/ssl/certs/wraith.crt;
    ssl_certificate_key /etc/ssl/private/wraith.key;

    location / {
        proxy_pass         http://127.0.0.1:5050;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

Then set:
```
DASHBOARD_ALLOWED_ORIGINS=https://wraith.internal.example.com
```

---

## Continuous Monitor Daemon

Run the monitor in the background:

```bash
# Linux/macOS — systemd or nohup
nohup py src/main.py monitor > logs/monitor.log 2>&1 &

# Docker
docker compose exec -d wraith python src/main.py monitor
```

Or add to your process manager (systemd, supervisor).

---

## PostgreSQL in Production

1. Create a database:
```sql
CREATE DATABASE wraith;
CREATE USER wraith WITH PASSWORD 'your-password';
GRANT ALL PRIVILEGES ON DATABASE wraith TO wraith;
```

2. Set the connection string:
```
DATABASE_URL=postgresql+psycopg2://wraith:your-password@localhost/wraith
```

3. Install the driver:
```bash
pip install psycopg2-binary
```

4. Initialize:
```bash
py src/main.py init
```

---

## Security Hardening

- **Bind to loopback**: Default `--host 127.0.0.1` prevents external access. Use a reverse proxy for external exposure.
- **TLS**: Always terminate TLS at the reverse proxy layer.
- **CORS**: Set `DASHBOARD_ALLOWED_ORIGINS` to your exact dashboard URL.
- **Secrets**: Never commit `.env` to version control. Use a secrets manager in production.
- **Log rotation**: Configured automatically (10 MB files, 5 backups). Forward to a SIEM for production.
