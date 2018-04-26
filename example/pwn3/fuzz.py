#!/usr/bin/env python
# coding=utf-8 """

"""
Module Name: Fuzzing.py
Create By  : Bluecake
Description: Automatically Fuzzing Module
"""

from emulator import *
from triton import *
from pwn import *


class Fuzzing(Emulator):
    
    """
    Parameters:
        @param binary: path of binary
        @param guesser: reusable function gueeser
        @param solver: reusable input solver
        @param solve_record: solver use record
        @param log_level: global log level
    """
    def __init__(self, binary, guesser=None, solver=None, solve_record=None, log_level=logging.INFO):

        super(Fuzzing, self).__init__(binary, log_level=log_level)

        self.binary = binary
        self.show_inst = False
        self.show_output = False

        if not guesser:
            self.guesser = Guesser(self.binary, log_level=log_level)
        else:
            self.guesser = guesser

        if not solver:
            # self.solver = InputSolver(self.binary, log_level=log_level)
            self.solver = InputSolver(self.binary)
        else:
            self.solver = solver

        if solve_record:
            self.solve_record = solve_record
        else:
            self.solve_record = {}

        self.call_record = {}
        # load information

    
    def __del__(self):
        # save information
        pass


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


    # """
    # Get function type at the entry of one function
    # """
    # def getFuncTypeAfterCall(self, pc):

    #     if self.push_count == 1:
    #         esp = self.getreg('esp')
    #         arg1 = self.getuint32(esp+4)
    #             
    #         if self.knownfunc.has_key(pc):
    #             result = self.knownfunc[pc]

    #         else:
    #             """
    #             Judge whether the first argument is pointer
    #             TODO: if need, add support for functions whose first argument is not pointer 
    #             """
    #             if not self.isValid(arg1):
    #                 return FUNCTYPE.FUNC_unk

    #             result = self.guesser.guessFunc(pc)
    #             self.knownfunc[pc] = result
    #             self.call_info[self.last_pc] = result

    #         return result

    #     return FUNCTYPE.FUNC_unk
    
    
    def getSolveRecord(self):
        return self.solve_record

    
    """
    Get what function to call before jump into
    """
    def getFuncTypeBeforeCall(self, pc):

        if self.push_count == 1:
            esp = self.getreg('esp')
            arg1 = self.getuint32(esp)
                
            """
            Judge whether the first argument is pointer
            TODO: if need, add support for functions whose first argument is not pointer 
            """
            if not self.isValid(arg1):
                return FUNCTYPE.FUNC_unk

            return self.guesser.guessCall(pc)

        return FUNCTYPE.FUNC_unk
    

    def analyse(self, pc):

        inst = Instruction()
        opcode = self.getMemory(pc, 16)
        inst.setOpcode(opcode)
        self.triton.disassembly(inst)

        if self.lastInstType == OPCODE.CALL:
            # print 'call ', hex(self.last_pc), self.func_depth
            # if self.getFuncType(pc) == FUNCTYPE.FUNC_atoi:
            #    print "atoi called"
            #    self.nextpc = pc + inst.getSize()                
            # elif self.getFuncType(pc) == FUNCTYPE.FUNC_strlen:
            #     print "strlen called"
            self.push_count = 0
            self.func_depth += 1

        elif self.lastInstType == OPCODE.RET:
            self.push_count = 0
            self.func_depth -= 1

        elif inst.getType() == OPCODE.PUSH:
            self.push_count += 1

        elif inst.getType() == OPCODE.CALL:

            """
            Record how many times a call instruction is called 
            at specific address
            """
            if self.call_record.has_key(pc):
                self.call_record[pc] += 1

            else:
                self.call_record[pc] = 1
            

            if self.getFuncTypeBeforeCall(pc) == FUNCTYPE.FUNC_atoi:
                # print 'call atoi', hex(pc)

                if self.solve_record.has_key((pc, self.call_record[pc])):
                    # already solved
                    return   

                title('atoi call record', self.call_record[pc])
                title('solve record before solve', self.solve_record)
                
                if self.call_record[pc] != 2:
                    return 

                self.solver.set_input(self.init_input, self.readcount)
                self.solver.set_breakpoint((pc, self.call_record[pc]))
                esp = self.getreg('esp')
                arg1 = self.getuint32(esp)
                for expect in ['1AAAAA', '11AAAA', '111AAA', '11111A']:
                    mem = range(arg1, arg1 + len(expect))
                    
                    self.solver.set_input(self.init_input, self.readcount)
                    answer = self.solver.solveMemory(mem, expect)
                    print answer
                    print self.solver.createInput(answer)
                
                self.solve_record[(pc, self.call_record[pc])] = True
                title('solve record after solve', self.solve_record)

            # elif self.getFuncTypeBeforeCall(pc) == FUNCTYPE.FUNC_strlen:
            #     print 'call strlen', hex(pc)


    def explorer(self, seed):
        
        title('seed', seed)
        inputs = []

        self.initialize()
        self.symbolize = True
        self.set_input(seed)
        self.init_input = seed
        pc = self.getpc()

        self.push_count = 0
        self.func_depth = 0
        self.nextpc = -1
        # connectPycharm('10.2.111.189')
        
        self.ForceSymbolize = True
        while pc:
            self.analyse(pc)
            # pc = self.parse_command()
            pc = self.process()
        
        Triton = self.triton
        astCtxt = Triton.getAstContext()
        previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue()) 
        pco = self.triton.getPathConstraints()

        for pc in pco:

            branches = pc.getBranchConstraints()
            for branch in branches:

                if branch['isTaken'] == False:
                    models = Triton.getModel(astCtxt.land([previousConstraints, branch['constraint']]))
                    answer = {}

                    for k, v in models.items():
                        self.log.debug(v)
                        index = int(v.getName().replace('SymVar_', ''))
                        answer[index] = chr(v.getValue())

                    # title('answer', answer)
                    if answer:
                        print hex(branch['dstAddr'])
                        self.solver.set_input(self.init_input, self.readcount)
                        inputs.append(self.solver.createInput(answer))

        return inputs

if __name__ == '__main__':
    # seeds = ['A']
    # seeds = [open('input1').read()]
    # seed_tried = []
    seed = ['\x9b\xcc\xae\x70AAAA']
    guesser = Guesser('./bin',log_level=logging.INFO)
    solver = InputSolver('./bin', log_level=logging.INFO)
    fuzzer = Fuzzing('./bin', guesser, solver, log_level=logging.INFO)
    new_inputs = fuzzer.explorer(seed[0])
    title('new_inputs', new_inputs)
    new_inputs2 = []
    for aInput in new_inputs:
        solve_record = fuzzer.getSolveRecord()
        fuzzer = Fuzzing('./bin', guesser, solver, solve_record, logging.INFO)
        result = fuzzer.explorer(aInput)
        title('fuzzing result', result)
        for row in result:
            if row not in new_inputs2:
                new_inputs2.append(row)
                print 'row is ', row
    print new_inputs2
    
