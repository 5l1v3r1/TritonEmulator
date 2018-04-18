#!/usr/bin/env python
# coding=utf-8

"""
Module name: Branch Solve Test
Create by: Bluecake
Descript: A demo to pass the first check
.text:0804894A                 push    [ebp+buffer]
.text:0804894D                 call    atoi
.text:08048952                 add     esp, 10h
.text:08048955                 mov     [ebp+size], eax
.text:08048958                 cmp     [ebp+size], 0
.text:0804895C                 js      short loc_8048967
"""

from emulator import *
from debugger import *
from utils import *

class SolveTest(Debugger):

    def __init__(self, binary, show=False, symbolize=True):
        super(SolveTest, self).__init__(binary, show=show, symbolize=symbolize)
        self.log = get_logger('solve.py')

    def branch1_test(self):
        self.initialize()
        log = self.log 
        
        log.info("branch1Test started");
        pc = self.getpc()
        while pc:
            if pc == 0x08048952:
                Triton = self.triton
                astCtxt = Triton.getAstContext()

                # Define constraint
                constraints = [Triton.getPathConstraintsAst()]

                # Slice expressions
                eax_symbol = Triton.getSymbolicExpressionFromId(Triton.getSymbolicRegisterId(Triton.registers.eax))
                eax_ast = eax_symbol.getAst()
                constraints.append(astCtxt.equal(eax_ast, astCtxt.bv(200, 32)))
                
                # for i in range(4):
                #     addr = 0x80ee0e0
                #     target_rip = 0xdeadbeaf
                #     input_expr = Triton.getSymbolicExpressionFromId(Triton.getSymbolicMemoryId(addr+i))
                #     input_ast = input_expr.getAst()
                #     byte_contraint = astCtxt.equal(input_ast, astCtxt.bv(target_rip >> (8*i) & 0xff, 8))
                #     constraints.append(byte_contraint)

                cstr  = astCtxt.land(constraints)

                print '[+] Asking for a model, please wait...'
                model = Triton.getModel(cstr)

                # Save new state
                for k, v in model.items():
                    print '[+]', v
                return

            pc = self.parse_command(pc)
            # self.process()
        
        log.info("branch1Test ended");

if __name__ == '__main__': 
    solver = SolveTest('./bin', show=False)
    solver.branch1_test()
