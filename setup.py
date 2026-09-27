from setuptools import setup, find_packages

setup(
    name="wraith",
    version="1.0.0",
    description="Credential Exposure Monitor — breach DB and paste site monitoring for red teams",
    author="xdrew87",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "aiohttp>=3.14.3",
        "click>=8.5.0",
        "colorama>=0.4.6",
        "pyyaml>=6.0.3",
        "python-dotenv>=1.2.3",
        "SQLAlchemy>=2.1.1",
        "rich>=15.0.0",
        "aiofiles>=25.1.0",
        "flask>=3.1.3",
        "flask-cors>=6.0.5",
        "flask-limiter>=4.1.1",
    ],
    entry_points={
        "console_scripts": [
            "wraith=main:cli",
        ],
    },
)
