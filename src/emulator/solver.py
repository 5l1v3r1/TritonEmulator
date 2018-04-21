#!/usr/bin/env python
# coding=utf-8

"""
Module Name: InputSolver.py
Create By  : Bluecake
Description: A class for symbolic solving
"""

from pwn import *
from emulator import *
from utils import *
import logging


class InputSolver(object):

    def __init__(self, binary, src, breakpoint, initInput='', log_level=logging.DEBUG):
        """
        Argumenst:
            binary, path of binary file
            src, memory address list of input
        """

        self.binary = binary
        self.initInput = initInput
        self.src = src
        self.log_level = log_level
        self.breakpoint = breakpoint 

        self.log = get_logger("solver.py", self.log_level) 


    """
    New and init an emulator
    """
    def initEmulator(self, show_inst=False, symbolize=False, isTaint=False):

        emulator = Emulator(self.binary, 
                show_inst=show_inst, 
                show_output=False,
                symbolize=symbolize, 
                isTaint=isTaint, 
                log_level=self.log_level)

        emulator.initialize()

        if self.initInput:
            # create pipe for SYSCALL read
            emulator.read, emulator.write = os.pipe()
            os.write(emulator.write, self.initInput + '\n')
        
        return emulator


    """
    Inner method for traceMemory()
    """
    def _traceMemory(self, src, dst):
        
        if len(src) == 1:
            return src

        left = src[ : len(src)/2]
        right = src[len(src)/2 : ]
        
        emulator = self.initEmulator(isTaint=True)
        emulator.taintable = left

        pc = emulator.getpc()
        while pc != self.breakpoint:
            pc = emulator.process()

        if emulator.isTainted(dst):
            new_left = self._traceMemory(left, dst)
        else:
            new_left = []

        emulator = self.initEmulator(isTaint=True)
        emulator.taintable = right

        pc = emulator.getpc()
        while pc != self.breakpoint:
            pc = emulator.process()
            
        if emulator.isTainted(dst):
            new_right = self._traceMemory(right, dst)
        else:
            new_right = []

        return new_left + new_right


    """
    Track source input of memory content
    """
    def traceMemory(self, dst):

        source = self._traceMemory(self.src, dst)
        return source


    """
    Get input data with expected value
    """ 
    def solveValue(self, mem, value):
        """
        Arguments:
            mem, address list of target memory we want to solve
            value, value list of target memory we expect to be
                or a uint32 or uint64 number
        """

        if type(value) == int:
            value = map(ord, p32(value)) 

        if len(mem) != len(value):
            self.log.warn("Mem and value length is not equal, please checkout")
            return False

        symbolized = self.traceMemory(mem)

        if not symbolized:
            return False
        
        emulator = self.initEmulator(symbolize=True)
        emulator.symbolized = symbolized

        pc = emulator.getpc()
        while pc != self.breakpoint:
            pc = emulator.process()
         
        Triton = emulator.triton
        astCtxt = Triton.getAstContext()
        constraints = [Triton.getPathConstraintsAst()]
        
        for i, v in enumerate(value):
            mem_id = Triton.getSymbolicMemoryId(mem[i])
            mem_sym = Triton.getSymbolicExpressionFromId(mem_id)
            mem_ast = mem_sym.getAst()
            constraints.append(astCtxt.equal(mem_ast, astCtxt.bv(value[i], 8)))

        cstr  = astCtxt.land(constraints)
        self.log.info('Asking for a model, please wait...')
        model = Triton.getModel(cstr)
        new_input = {}
        for k, v in model.items():
            self.log.info(v)
            index = int(v.getName().replace('SymVar_', ''))
            new_input[symbolized[index]] = chr(v.getValue())
        
        return new_input
