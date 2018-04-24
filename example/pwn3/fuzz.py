#!/usr/bin/env python
# coding=utf-8 """

"""
Module Name: Fuzzing.py
Create By  : Bluecake
Description: Automatically Fuzzing Module
"""

from emulator import *
from triton import *

class Fuzzing(Debugger):
    
    def __init__(self, binary, log_level=logging.INFO):
        """
        Arguments:
            binary, path of binary
        """
        self.binary = binary
        super(Fuzzing, self).__init__(binary, log_level=log_level)
        self.show_inst = False
        self.show_output = False
        self.guesser = Guesser(self.binary, log_level=log_level)
        self.knownfunc = {}

    
    """
    Check whether an instruction is a jmp instruction
    """
    def isJumpInst(self, instType):

        JMP_TYPE = [OPCODE.JA, OPCODE.JAE, OPCODE.JB, OPCODE.JBE, 
                OPCODE.JE, OPCODE.JG, OPCODE.JGE, OPCODE.JL, 
                OPCODE.JLE, OPCODE.JNE, OPCODE.JNO, OPCODE.JNP, 
                OPCODE.JNS, OPCODE.JO, OPCODE.JP, OPCODE.JS]

        if instType in JMP_TYPE:
            return True

        else:
            return False


    def getFuncType(self, pc):

        if self.push_count == 1:
            esp = self.getreg('esp')
            arg1 = self.getuint32(esp+4)

                
            if self.knownfunc.has_key(pc):
                result = self.knownfunc[pc]

            else:
                """
                Judge whether the first argument is pointer
                TODO: if need, add support for functions whose first argument is not pointer 
                """
                if not self.isValid(arg1):
                    return FUNCTYPE.FUNC_unk

                result = self.guesser.guessFunc(pc)
                self.knownfunc[pc] = result

            return result

        return FUNCTYPE.FUNC_unk
    

    """
    Retrive called function
    """
    def analyse(self, pc):

        inst = Instruction()
        opcode = self.getMemory(pc, 16)
        inst.setOpcode(opcode)
        self.triton.disassembly(inst)

        if self.lastInstType == OPCODE.CALL:
            if self.getFuncType(pc) == FUNCTYPE.FUNC_atoi:
                print "atoi called"
            elif self.getFuncType(pc) == FUNCTYPE.FUNC_strlen:
                print "strlen called"

            self.push_count = 0
            self.func_depth += 1

        elif self.lastInstType == OPCODE.RET:
            self.push_count = 0
            self.func_depth -= 1

        elif inst.getType() == OPCODE.PUSH:
            self.push_count += 1


    def explorer(self):
        
        self.initialize()
        pc = self.getpc()

        level = 2
        self.push_count = 0
        self.func_depth = 0
        # connectPycharm('10.2.111.189')

        while pc:
            self.analyse(pc)
            pc = self.parse_command() 



if __name__ == '__main__':
    fuzzer = Fuzzing('./bin', logging.INFO)
    fuzzer.explorer()
    print fuzzer.knownfunc

