from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="payload-generator",
    version="1.0.0",
    author="Security Researcher",
    author_email="security@example.com",
    description="A comprehensive payload generation tool for web exploitation testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/username/payload-generator",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: Microsoft :: Windows",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "payload-gen=src.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["data/payloads/*.json", "data/templates/*.json"],
    },
    keywords="security, payload, xss, sqli, command-injection, burp-suite, penetration-testing",
    project_urls={
        "Bug Reports": "https://github.com/username/payload-generator/issues",
        "Source": "https://github.com/username/payload-generator",
        "Documentation": "https://github.com/username/payload-generator/docs",
    },
)
