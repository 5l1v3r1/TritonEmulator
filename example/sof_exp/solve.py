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
from triton import OPCODE
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

            try:
                pc = self.parse_command(pc)

            except IllegalPcException:
                if self.lastInstType == OPCODE.RET:

                    Triton = self.triton
                    astCtxt = Triton.getAstContext()

                    constraint = [Triton.getPathConstraintsAst()]

                    target_pc = 0xdeadbeaf
                    esp = self.getreg('esp')
                    print hex(esp)
                    ret_addr = esp - 4
                    for i in range(4):
                        mem_sym = Triton.getSymbolicExpressionFromId(Triton.getSymbolicMemoryId(ret_addr + i))
                        print mem_sym
                        mem_ast = mem_sym.getAst()
                        new_ast = astCtxt.equal(mem_ast, astCtxt.bv(target_pc >> (i*8) & 0xff, 8))
                        constraint.append(new_ast)

                    print constraint
                    cstr  = astCtxt.land(constraint)

                    print '[+] Asking for a model, please wait...'
                    model = Triton.getModel(cstr)

                    # Save new state
                    for k, v in model.items():
                        print '[+]', v

                sys.exit(0)

        log.info("test1 ended");

if __name__ == '__main__': 
    solver = SolveTest('./bof', show=True)
    solver.test_crash()
