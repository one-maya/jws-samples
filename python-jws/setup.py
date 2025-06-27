from setuptools import setup, find_packages

setup(
    name="python-jws-example",
    version="1.0.0",
    description="Example project demonstrating JSON Web Signature (JWS) in Python",
    author="",
    author_email="",
    packages=find_packages(),
    install_requires=[
        "PyJWT==2.8.0",
        "cryptography==41.0.7"
    ],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
    ],
    keywords="jws json-web-signature jwt python",
)