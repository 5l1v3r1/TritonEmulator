#!/usr/bin/env python
# coding=utf-8 """

"""
Module Name: Fuzzer.py
Create By  : Bluecake
Description: Automatically Fuzzing Module
"""

from emulator import *
from guesser import *
from solver import *
from triton import *
from pwn import *


class Fuzzer(object):
    
    """
    Parameters:
        @param binary: path of binary
        @param guesser: reusable function gueeser
        @param solver: reusable input solver
        @param solve_record: solver use record
        @param log_level: global log level
    """
    def __init__(self, binary, log_level=logging.INFO):

        self.binary = binary
        self.log_level = log_level
        self.log = get_logger('fuzzer.py', log_level)

        self.guesser = Guesser(self.binary, log_level=log_level)
        self.solver = InputSolver(self.binary, log_level=log_level)

        bin_root = os.path.dirname(os.path.abspath(binary))
        self.config_file = bin_root + '/solve_record.txt'
        if os.path.exists(self.config_file):
            data = open(self.config_file).read()
            self.solve_record = eval(data)
        else:
            self.solve_record = {}

        self.interesting_seeds = []
        self.boring_seeds = []
        self.branch_choosen = []
        self.tried_seed = []
    

    def __del__(self):
        open(self.config_file, 'wb').write(repr(self.solve_record))


    """
    Get what function to call before jump into
    """
    def getFuncTypeBeforeCall(self, emulator, pc):

        if self.push_count == 1:
            esp = emulator.getreg('esp')
            arg1 = emulator.getuint32(esp)
                
            """
            Judge whether the first argument is pointer
            TODO: if need, add support for functions whose first argument is not pointer 
            """
            if not emulator.isValid(arg1):
                return FUNCTYPE.FUNC_unk

            return self.guesser.guessCall(pc)

        return FUNCTYPE.FUNC_unk
    

    def analyse(self, emulator, pc, seed):

        inst = Instruction()
        opcode = emulator.getMemory(pc, 16)
        inst.setOpcode(opcode)
        emulator.triton.disassembly(inst)

        if emulator.lastInstType == OPCODE.CALL:
            self.push_count = 0
            self.func_depth += 1

        elif emulator.lastInstType == OPCODE.RET:
            self.push_count = 0
            self.func_depth -= 1

        elif inst.getType() == OPCODE.PUSH:
            self.push_count += 1

        elif inst.getType() == OPCODE.CALL:

            if self.getFuncTypeBeforeCall(emulator, pc) == FUNCTYPE.FUNC_atoi:
                title('atoi call record')

                if self.solve_record.has_key((pc, emulator.inst_count)):
                    # already solved
                    return   

                self.solver.set_input(seed, emulator.readcount)
                self.solver.set_breakpoint((pc, emulator.inst_count))
                esp = emulator.getreg('esp')
                arg1 = emulator.getuint32(esp)
                
                solve_seeds = []
                for expect in ['1AAAAA', '11AAAA', '111AAA', '11111A']:
                    mem = range(arg1, arg1 + len(expect))
                    self.solver.set_input(seed, emulator.readcount)
                    answer = self.solver.solveMemory(mem, expect)

                    if answer:
                        new_seed = self.solver.createInput(answer)
                        self.interesting_seeds.append(new_seed) 
                        solve_seeds.append(new_seed)

                self.solve_record[(pc, emulator.inst_count)] = solve_seeds

            """
            if find printf function, check whether format string is controllable
            """
            # elif self.getFuncTypeBeforeCall(pc) == FUNCTYPE.FUNC_printf:
                
                
            # elif self.getFuncTypeBeforeCall(pc) == FUNCTYPE.FUNC_strlen:
            #     print 'call strlen', hex(pc)


    def explorer(self, emulator, seed):
        
        if seed in self.tried_seed:
            return

        self.tried_seed.append(seed)
        title('seed', seed)

        emulator.initialize()
        emulator.symbolize = True
        emulator.set_input(seed)
        pc = emulator.getpc()

        self.push_count = 0
        self.func_depth = 0
        self.nextpc = -1
        # connectPycharm('10.2.111.189')
        
        emulator.ForceSymbolize = True
        while pc:
            if pc == 0x08048AF8:
                title('find it', (pc, seed))
                emulator.parse_command()
                sys.exit()
            # self.analyse(emulator, pc, seed)
            # pc = self.parse_command()
            pc = emulator.process()
        
        Triton = emulator.triton
        astCtxt = Triton.getAstContext()
        previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue()) 
        pco = emulator.triton.getPathConstraints()

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

                    if answer:
                        title('answer', answer)
                        self.solver.set_input(seed, emulator.readcount)
                        new_seed = self.solver.createInput(answer)
                        if branch['dstAddr'] in self.branch_choosen:
                            self.boring_seeds.append(new_seed)
                        else:
                            self.interesting_seeds.append(new_seed)
                else:
                    self.branch_choosen.append(branch['dstAddr'])
    
    def initEmulator(self):
        emulator = Emulator(self.binary, log_level = self.log_level)
        emulator.show_inst = False
        emulator.show_output = False
        return emulator

    def fuzz(self):
        seeds = ['A']
        
        for i in range(3):
            self.interesting_seeds = []
            self.boring_seeds = []

            for seed in seeds:
                emulator = self.initEmulator()
                self.explorer(emulator, seed)

            title('intererting', self.interesting_seeds)
            title('boring', self.boring_seeds)
            
            seeds = self.interesting_seeds
            self.interesting_seeds = []
            for seed in seeds:
                emulator = self.initEmulator()
                self.explorer(emulator, seed)

            title('intererting', self.interesting_seeds)
            title('boring', self.boring_seeds)

            seeds = self.interesting_seeds + self.boring_seeds
        title('seeds', seeds)

