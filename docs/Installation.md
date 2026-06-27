# WRAITH — Installation Guide

## Requirements

- Python 3.10 or later
- pip
- Git

Optional: Docker and docker-compose for containerized deployment.

---

## Standard Installation

```bash
# Clone the repository
git clone https://github.com/xdrew87/wraith.git
cd wraith

# Install Python dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Edit .env with your API keys
# (see Configuration.md for details)

# Initialize the database
py src/main.py init
```

---

## Virtual Environment (Recommended)

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

---

## Docker Installation

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env

# Build and start
docker compose up -d

# Verify the service is running
curl http://localhost:5050/api/v1/health
```

---

## Verify Installation

```bash
py src/main.py --help
py src/main.py init
py src/main.py scan example.com --feeds hibp
```

If no API keys are configured, feeds will be skipped but the tool will run without errors.

---

## Database Location

By default, WRAITH creates `wraith.db` in the project root. To use a custom path:

```yaml
# config.yaml
database:
  sqlite_path: "/data/wraith.db"
```

Or for PostgreSQL:
```
DATABASE_URL=postgresql+psycopg2://user:pass@localhost/wraith
```

---

## Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
