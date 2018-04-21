#!/usr/bin/env python
# coding=utf-8

"""
Module      : solver.py 
Create By   : Bluecake
Description : A simple test for class Exploiter
"""

from emulator import *
import logging

class Solver:

    def __init__(self, binary, crash):
        self.binary = binary
        self.crash = crash


    def run(self):
        exp = Exploiter(self.binary, self.crash, log_level=logging.INFO)
        if exp.getCrashType() == crash.CONTROL_PC:
            src = exp.getCrashMemory()
            target = 0xdeadbeaf
            new_src = exp.pcPayload(target)
            new_input = exp.createInput(new_src)
            print new_src
            with open('eip.in', 'wb') as f:
                f.write(new_input)
            print new_input

        elif exp.getCrashType() == crash.SHELLCODE:
            pass

        else:
            return False


if __name__ == '__main__':
    solver = Solver('./bof', './crash.in')
    solver.run()

