#!/usr/bin/env python
# coding=utf-8

from setuptools import setup, find_packages
import sys, os

try:
    import triton
except Exception as e:
    print("Running emulator needs Triton")
    print("More information, please refer to https://github.com/JonathanSalwan/Triton")
    sys.exit(-1)

os.system('cp peda /usr/share/peda -r')

setup(
    name="emulator",
    version="1.0",
    author="bluecake",
    author_email="bluekezhou@qq.com",
    description=("An emulator tool for linux x86(32bit and 64bit) program"),
    license="BSD",
    keywords="triton emulator",
    url="https://github.com/Bluekezhou/TritonEmulator",
    packages=find_packages("src"),
    package_dir = { "":"src" },
    install_requires=[
        'pwntools',
    ],
)
