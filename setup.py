from setuptools import setup, find_packages

setup(
    name="netscout",
    version="2.0.0",
    description="NetScout PRO — Network Intelligence & Security Scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Avinash Bhondave",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests*"]),
    entry_points={"console_scripts": ["netscout=netscout:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
    ],
    install_requires=[],
    extras_require={"dev": ["pytest>=7.0"]},
)
