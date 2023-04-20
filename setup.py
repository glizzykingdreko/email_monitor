from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="email_monitor",
    version="0.1.0",
    author="glizzykingdreko",
    author_email="glizzykingdreko@protonmail.com",
    description="A versatile IMAP mail monitoring module with Gmail API support, regex queries, and flexible search options",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/glizzykingdreko/email_monitor",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    python_requires=">=3.8",
    install_requires=[
        "google-auth-oauthlib",
        "google-auth-httplib2",
        "google-api-python-client",
    ],
)
