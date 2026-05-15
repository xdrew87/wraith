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
        "aiohttp>=3.9.0",
        "click>=8.1.0",
        "colorama>=0.4.6",
        "pyyaml>=6.0.1",
        "python-dotenv>=1.0.0",
        "SQLAlchemy>=2.0.0",
        "rich>=13.0.0",
        "aiofiles>=23.0.0",
        "flask>=3.0.0",
        "flask-cors>=4.0.0",
    ],
    entry_points={
        "console_scripts": [
            "wraith=main:cli",
        ],
    },
)
