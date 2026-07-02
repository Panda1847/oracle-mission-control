"""ORACLE setup.py"""
from setuptools import setup, find_packages

setup(
    name="oracle-redteam",
    version="3.2.0",
    description="ORACLE — Autonomous AI Red Team Intelligence System",
    packages=find_packages(),
    package_data={"oracle": ["data/*.json", "data/*.json.gz", "web/static/vendor/*.js"]},
    python_requires=">=3.10",
    install_requires=[
        "PyYAML>=6.0",
        "rich>=13.0",
        "requests>=2.28",
        "pexpect>=4.8",
        "tomli>=2.0; python_version<'3.11'",
        "cryptography>=42.0",
        "jinja2>=3.1",
    ],
    extras_require={
        "web": ["flask>=2.3", "flask-socketio>=5.3"],
    },
    entry_points={
        "console_scripts": [
            "oracle=oracle.cli.main:main",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
