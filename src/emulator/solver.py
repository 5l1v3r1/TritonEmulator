#!/usr/bin/env python
# coding=utf-8

"""
Module Name: InputSolver.py
Create By  : Bluecake
Description: A class for symbolic solving
"""

from pwn import *
import logging

from emulator import *
from debugger import *
from utils import *


class InputSolver(object):

    """
    Arguments:
        @param binary: path of binary file
        @param src: memory address list of input
        @param initInput: input data for program
    """
    def __init__(self, binary, log_level=logging.DEBUG):

        self.binary = binary
        self.init_input = ''
        self.log_level = log_level
        self.log = get_logger("solver.py", log_level) 
        self.track_record = {}

    
    def set_input(self, init_input, input_len):
        self.input_len = input_len
        self.init_input = init_input.ljust(input_len, 'A')
    

    def set_breakpoint(self, breakpoint):
        self.breakpoint = breakpoint


    """
    New and init an emulator
    """
    def initEmulator(self, symbolize=False, isTaint=False):

        emulator = Debugger(self.binary, log_level=self.log_level)
        emulator.show_inst = False
        emulator.show_output = False
        emulator.symbolize = symbolize
        emulator.isTaint = isTaint

        emulator.initialize()
        if self.init_input:
            emulator.set_input(self.init_input)
        
        return emulator


    """
    Inner method for traceMemory
    Parameters:
        @param src: input offset list 
        @param dst: target memory address list or register name that we need to control 
    """
    def _traceMemory(self, src, dst):
        title('src', src) 
        if len(src) == 1:
            return src

        left = src[ : len(src)/2]
        right = src[len(src)/2 : ]
        
        emulator = self.initEmulator(isTaint=True)
        # title('[1]emulator.stdin', emulator.stdin.encode('hex'))
        emulator.taint_list = left

        pc = emulator.getpc()
        breakaddr, breakcount = self.breakpoint

        while True:
            if pc == breakaddr:
                breakcount -= 1
                if breakcount == 0:
                    break
            pc = emulator.process()

        if type(dst) == str:
            Triton = emulator.triton
            dst = eval('Triton.registers.' + dst)
        
        if emulator.isTainted(dst):
            new_left = self._traceMemory(left, dst)
        else:
            new_left = []

        emulator = self.initEmulator(isTaint=True)
        # title('[2]emulator.stdin', emulator.stdin.encode('hex'))
        emulator.taint_list = right

        if type(dst) == str:
            Triton = emulator.triton
            dst = eval('Triton.registers.' + dst)

        pc = emulator.getpc()
        breakaddr, breakcount = self.breakpoint

        while True:
            if pc == breakaddr:
                breakcount -= 1
                if breakcount == 0:
                    break
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
        title('traceMemory', dst)
        title('input_len', self.input_len)
        src = range(self.input_len)
        # if self.input_len > 0x10: # inputs length is less than 0x10, it's not necessary to track
        if self.input_len > 0: # inputs length is less than 0x10, it's not necessary to track
            source = self._traceMemory(src, dst)
            return source

        else:
            return src


    """
    Get input data with memory constraints
    """ 
    def solveMemory(self, mem, value):
        """
        Arguments:
            mem, address list of target memory we want to solve
            value, value list of target memory we expect to be
                or a uint32 or uint64 number
        """
        # connectPycharm('127.0.0.1')

        if type(value) == int:
            value = map(ord, p32(value)) 
        
        elif type(value) == str:
            value = map(ord, value)


        if len(mem) != len(value):
            self.log.warn("Mem and value length is not equal, please checkout")
            return False

        if self.track_record.has_key((self.breakpoint, self.input_len)):
            symbolize_list = self.track_record[(self.breakpoint, self.input_len)]

        else:
            symbolize_list = self.traceMemory(mem)
            if not symbolize_list:
                return False
            self.track_record[(self.breakpoint, self.input_len)] = symbolize_list
        
        title('symbolize_list', symbolize_list)
        title('start solve')
        emulator = self.initEmulator(symbolize=True)
        emulator.symbolize_list = symbolize_list

        pc = emulator.getpc()
        breakaddr, breakcount = self.breakpoint

        while True:
            if pc == breakaddr:
                breakcount -= 1
                if breakcount == 0:
                    break
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
            new_input[symbolize_list[index]] = chr(v.getValue())
        
        return new_input


    """
    Get input data with register constraints
    Parameters:
        @param reg: register name we want to solve
        @param value: value we expected 
    """ 
    def solveRegister(self, reg, value):
        
        if self.track_record.has_key((self.breakpoint, self.input_len)):
            symbolize_list = self.track_record[(self.breakpoint, self.input_len)]

        else:
            symbolize_list = self.traceMemory(reg)
            if not symbolize_list:
                return False
            self.track_record[(self.breakpoint, self.input_len)] = symbolize_list

        emulator = self.initEmulator(symbolize=True)
        emulator.symbolize_list = symbolize_list

        Triton = emulator.triton


        pc = emulator.getpc()
        breakaddr, breakcount = self.breakpoint

        while True:
            if pc == breakaddr:
                breakcount -= 1
                if breakcount == 0:
                    break
            pc = emulator.process()
         
        Triton = emulator.triton
        treg = eval('Triton.registers.' + reg)
        astCtxt = Triton.getAstContext()
        constraints = [Triton.getPathConstraintsAst()]
        
        reg_id = Triton.getSymbolicRegisterId(treg)
        reg_sym = Triton.getSymbolicExpressionFromId(reg_id)
        reg_ast = reg_sym.getAst()
        constraints.append(astCtxt.equal(reg_ast, astCtxt.bv(value, 32)))

        cstr  = astCtxt.land(constraints)
        self.log.debug('Asking for a model, please wait...')
        model = Triton.getModel(cstr)
        new_input = {}
        for k, v in model.items():
            self.log.debug(v)
            index = int(v.getName().replace('SymVar_', ''))
            new_input[symbolize_list[index]] = chr(v.getValue())
        
        return new_input

    """
    Create input stream with solve answer
    """
    def createInput(self, answer, blank='a'):
        
        inputBuffer = ''
        for offset in range(self.input_len):
            if answer.has_key(offset):
                inputBuffer += answer[offset]

            elif self.init_input:
                inputBuffer += self.init_input[offset]

            else:
                inputBuffer += blank

        return inputBuffer
