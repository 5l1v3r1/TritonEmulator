#!/bin/python

"""
Module Name: Syscall Helper
Create by  : Bluecake
Description: Just provide syscall hook methods
"""


import i386_constant as SYS
from utils import *
import os


log = get_logger('syscall.py', logging.INFO)


def syscall_read(fd, addr, length, emulator): 
    log.debug('[SYS_read] fd: %d, addr: 0x%x, length: %x' % (fd, addr, length))
    
    if fd == 0:
        if emulator.read:
            content = os.read(emulator.read, length) 
        else:
            content = raw_input()
            if len(content) < length and not content.endswith('\n'):
                content += '\n'
            else:
                content = content[:length]
    else:
        content = os.read(fd,  length)
        
    emulator.triton.setConcreteMemoryAreaValue(addr, content)
    emulator.setreg('eax', len(content))
    return True

def syscall_write(fd, addr, length, emulator):
    log.debug('[SYS_write] fd: %d, addr: 0x%x, length: %x' % (fd, addr, length))
    content = emulator.getMemory(addr, length)
    os.write(fd, content)
    emulator.setreg('eax', len(content))
    return False

def syscall_execve():
    sys.exit(-1)

def syscall_mmap2():
    sys.exit(-1)

###################################################################################

SYS_Table = {
    int(SYS.__NR_read):   {"handler": syscall_read,   "constant": SYS.__NR_read},
    int(SYS.__NR_write):  {"handler": syscall_write,  "constant": SYS.__NR_write},
    int(SYS.__NR_execve): {"handler": syscall_execve, "constant": SYS.__NR_execve},
    int(SYS.__NR_mmap2):  {"handler": syscall_mmap2,  "constant": SYS.__NR_mmap2},
}

for SYSCALL, value in SYS.__dict__.items():
    if SYSCALL.startswith('__NR_') and not SYS_Table.has_key(int(value)):
        SYS_Table[int(value)] = {"handler": False, "constant":value}

###################################################################################


def syscall(sysnum, *args):
    if SYS_Table.has_key(sysnum):
        if SYS_Table[sysnum]["handler"] != False:
            log.info('Emulate syscall ' + str(SYS_Table[sysnum]["constant"]))
            return SYS_Table[sysnum]["handler"](*args) 
        else:
            log.warn('No support for syscall ' + str(SYS_Table[sysnum]["constant"]))
            return False
    else:
        log.warn('Unknown syscall ' + str(sysnum))
        return False

