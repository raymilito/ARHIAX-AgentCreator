from setuptools import setup, find_packages

setup(
    name="arhiax-sdk",
    version="1.0.0",
    description="SDK para crear agentes gobernados bajo estándar ARHIAX",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "httpx>=0.27.0",
        "pydantic>=2.0.0",
    ],
    extras_require={
        "anthropic": ["anthropic>=0.40.0"],
        "dev": ["pytest>=8.0.0", "pytest-asyncio>=0.23.0", "uvicorn>=0.30.0"],
    },
)
