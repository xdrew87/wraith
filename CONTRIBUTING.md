# Contributing to WRAITH

Thank you for your interest in contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/wraith.git`
3. Create a branch: `git checkout -b feat/your-feature-name`
4. Install dependencies: `py -m pip install -r requirements.txt`
5. Copy env template: `cp .env.example .env`

## Development Setup

```powershell
cd wraith
py -m pip install -r requirements.txt
py -m pytest tests/ -v
```

## Adding a New Feed

1. Create `src/feeds/sourcename.py`
2. Inherit from `BaseFeed` in `src/feeds/base.py`
3. Implement `async def lookup(self, target: str, target_type: str) -> dict`
4. Register the feed in `src/core/aggregator.py` `FEED_CLASSES` dict
5. Add API key config to `config.yaml` and `.env.example`
6. Write tests in `tests/test_feeds.py`

## Commit Style

Use conventional commits:

```
feat: add new breach source integration
fix: handle rate limit on HIBP API
refactor: extract domain validator to utils
docs: update feed integration guide
security: sanitize paste content before storage
```

## Pull Request Checklist

- [ ] Tests pass: `py -m pytest tests/ -v`
- [ ] No hardcoded credentials
- [ ] New feeds inherit from BaseFeed
- [ ] `.env.example` updated for any new API keys
- [ ] README updated if usage changed

## Code Style

- Python 3.10+
- 4-space indentation
- Type hints on all functions
- Docstrings on classes and public methods
- No inline API calls outside feed classes
