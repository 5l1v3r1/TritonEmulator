#!/usr/bin/env python
# coding=utf-8

from emulator import *

binary = './bin'
fuzzer = Fuzzer(binary, log_level=logging.INFO)
fuzzer.fuzz()
