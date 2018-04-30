#!/usr/bin/env python
# coding=utf-8

"""
Module Name: Guesser.py
Create by: Bluecake
Description: A class to guess function of target code
"""

from triton import OPCODE
import logging

from emulator import *
from debugger import *


###############################################################################
#                          Emulation Exception                                #
###############################################################################
class UnsupportedTypeException(Exception):
    def __init__(self, arg):
        if arch == 'x86':
            Exception.__init__(self, "Unsupported arg type %s: %s" % (str(type(arg))), str(arg))
        else:
            raise UnsupportArchException(arch)


##############################################################################
class FUNCTYPE:
    FUNC_unk = 0
    FUNC_atoi = 1
    FUNC_strlen = 2


func_table = {

    FUNCTYPE.FUNC_atoi: [
        {
            'input' : ["1000\x00"],
            'expect': {'ret':1000}
        },
        {
            'input' : ["  234\x00"],
            'expect': {'ret': 234}
        },
        {
            'input' : ["ABC234\x00"],
            'expect': {'ret':0}
        },
        {
            'input' : ["-1\x00"],
            'expect': {'ret':0xffffffff}
        },
    ],

    FUNCTYPE.FUNC_strlen: [
        {
            'input' : ["a\x00"],
            'expect': {'ret':1}
        },
        {
            'input' : ["1aa\x2fbd3\x00"],
            'expect': {'ret':7}
        },
        {
            'input' : ["\x001aa\x2fbd3\x00"],
            'expect': {'ret':0}
        },
    ]
    # FUNCTYPE.FUNC_printf: [
    #     {
    #         'input' : [ "%x\n\x00", 0xdeadbeaf],
    #         'expect': {'ret':1, }
    #     },
    # ]
}


###############################################################################                  
#                                  Main Class                                 #
###############################################################################
class Guesser(Debugger):

    def __init__(self, binary, log_level=logging.INFO):

        super(Guesser, self).__init__(binary, log_level=log_level)
        self.binary = binary
        self.checkAccess(False)
        # self.load_binary()
        self.initialize()
        self.show_inst = False
        self.show_output = False
        self.log = get_logger('guesser.py', log_level)
       
        bin_root = os.path.dirname(os.path.abspath(binary))
        self.config_file = bin_root + '/functions.txt'
        if os.path.exists(self.config_file):
            data = open(self.config_file).read()
            self.func_info, self.call_info = eval(data)
        else:
            self.call_info = {}  # store which function is called
            self.func_info = {}  # store which it is in
        

    """
    Store function information info file
    """
    def __del__(self):
        config = (self.func_info, self.call_info)
        open(self.config_file, 'wb').write(repr(config))

    """
    Set arguments in the given stack
    """
    def fillArgs(self, esp, sample):

        sample_input = sample['input']
        data_addr = esp + 0x100
        arg_addr = esp + 4

        # clear stack  
        self.writeMemory(esp, '\x00'*0x100)
        # Make sure it won't trigger IllegalPcException
        self.writeMemory(esp, self.getpc())

        for index, arg in enumerate(sample_input):

            if type(arg) == str:
                self.writeMemory(arg_addr, data_addr)
                self.writeMemory(data_addr, arg + "\x00")
                data_addr += len(arg) + 2

            elif type(arg) == int:
                self.writeMemory(arg_addr, arg) 

            else:
                raise NotImplementedException()
            
            arg_addr += 4

    
    """
    Check return value of specific input
    """
    def checkResult(self, sample):

        sample_output = sample['expect']
        for ret_type, value in sample_output.items():

            if ret_type == 'ret':
                ret = self.getret()

                if ret != value:
                    return False

                else:
                    return True

            else:
                raise NotImplementedException()

    
    """
    Test function with give sample
    """
    def checkSample(self, entry, sample):
        
        esp = self.getreg('esp')
        self.fillArgs(esp, sample)

        depth = 0
        self.setpc(entry)
        pc = self.getpc()

        while pc:
            pc = self.process()

            if self.SyscallFail:
                self.SyscallFail = False
                return False

            if self.lastInstType == OPCODE.CALL:
                depth += 1

            elif self.lastInstType == OPCODE.RET:
                depth -= 1

                # function is finished
                if depth == -1:
                    break
        
        if self.checkResult(sample):
            return True 

        else:
            return False
         
    
    """
    Check a given function with specific type
    """
    def tryFunc(self, entry, functype):

        samples = func_table[functype] 
        for sample in samples:
            if not self.checkSample(entry, sample):
                self.log.debug('[0x%x] function check failed with sample %s' 
                        % (entry, repr(sample['input'])))               
                return False
        
        self.log.debug('[0x%x] function check passed with sample %s' 
                % (entry, repr(sample['input']))                )
        return True


    """
    Export:
        Speculate the real function with entry of an unknown function
    """
    def guessFunc(self, entry):

        if self.func_info.has_key(entry):
            return self.func_info[entry]

        for functype in func_table:
            if self.tryFunc(entry, functype):
                self.func_info[entry] = functype
                return functype
        
        return FUNCTYPE.FUNC_unk


    """
    Export:
        Speculate the real called function, like call 0x804831(atoi)
    """
    def guessCall(self, pc):
        
        if self.call_info.has_key(pc):
            return self.call_info[pc]

        self.setpc(pc)
        self.process()
        entry = self.getpc()
        functype = self.guessFunc(entry)
        self.call_info[pc] = functype
        return functype


if __name__ == '__main__':

    guesser = Guesser('./bin')
    print guesser.guessFunc(0x0804DF40)
    print guesser.guessCall(0x08048967)



