#!/usr/bin/env python
# coding=utf-8

"""
Module name: Branch Solve Test
Create by: Bluecake
Descript: A demo to pass the first check


"""

from emulator import *
import os
from pwn import u32

class SolveTest(Debugger):

    def __init__(self, binary, show=False, symbolize=True):
        super(SolveTest, self).__init__(binary, show=show, symbolize=symbolize)
        self.log = get_logger('solve.py', logging.DEBUG)

        # create pipe for SYSCALL read
        r, w = os.pipe()
        self.read = r
        self.write = w


    def test_crash(self):
        self.initialize()
        log = self.log 
        
        log.info("test1 started");
        pc = self.getpc()

        with open('./crash.in', 'rb') as f:
            data = f.read()
            os.write(self.write, data)
            os.write(self.write, "\n")
        
        while pc:
            if not self.isValid(pc): 
                print "invalid pc address", hex(pc)
                sys.exit(0)
            pc = self.parse_command(pc)


        log.info("test1 ended");

if __name__ == '__main__': 
    solver = SolveTest('./bof', show=True)
    solver.test_crash()
