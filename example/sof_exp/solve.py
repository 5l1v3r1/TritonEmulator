#!/usr/bin/env python
# coding=utf-8

"""
Module      : solver.py 
Create By   : Bluecake
Description : A simple test for class Exploiter
"""

from emulator import *

class Solver:

    def __init__(self, binary, crash):
        self.binary = binary
        self.crash = crash


    def run(self):
        exp = Exploiter(self.binary, self.crash)
        if exp.getCrashType() == crash.CONTROL_PC:
            src = exp.getCrashMemory()
            target = [0xde, 0xed, 0xbe, 0xaf]
            new_src = exp.solveValue(src, target)
            print new_src

        elif exp.getCrashType() == crash.SHELLCODE:
            pass

        else:
            return False


if __name__ == '__main__':
    solver = Solver('./bof', './crash.in')
    solver.run()

