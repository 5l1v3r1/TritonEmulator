#!/bin/python

"""
Module Name: Syscall Helper
Create by  : Bluecake
Description: Just provide syscall hook methods
"""

import os, sys
from utils import *
import logging


class Syscall(object):

    def __init__(self, arch, log_level=logging.DEBUG):

        self.log = get_logger('syscall.py', log_level)
        if arch == 'x86':
            import i386_syscall as SYS
        else:
            raise UnsupportArchException(arch)

        self.systable = {}

        hook_syscall = ['read', 'write', 'exit']
        for aSyscall in hook_syscall:
            constant = getattr(SYS, 'SYS_' + aSyscall)
            handler = getattr(self, 'syscall_' + aSyscall)
            self.systable[int(constant)] = {"handler": handler, "name": str(constant)}

        for SYSCALL, value in SYS.__dict__.items():
            if SYSCALL.startswith('SYS_') and not self.systable.has_key(int(value)):
                self.systable[int(value)] = {"handler": None, "name": str(value)}


    def syscall_read(self, fd, addr, length, emulator): 
        self.log.debug('[SYS_read] fd: %d, addr: 0x%x, length: %x' % (fd, addr, length))
        
        if fd == 0:
            if hasattr(emulator, 'read'):
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
        return len(content)


    def syscall_write(self, fd, addr, length, emulator):
        self.log.debug('[SYS_write] fd: %d, addr: 0x%x, length: %x' % (fd, addr, length))
        content = emulator.getMemory(addr, length)
        os.write(fd, content)
        emulator.setreg('eax', len(content))
        return False


    def syscall_execve(self):
        sys.exit(-1)

    def syscall_mmap2(self):
        sys.exit(-1)

    def syscall_exit(self, *args):
        self.log.debug('[SYS_exit] exit(%d)' % args[0])
        emulator.running = True
        # Maybe it's not a good idea to kill the emulator
        # sys.exit(args[0])


    def syscall(self, sysnum, *args):
        log = self.log

        if self.systable.has_key(sysnum):
            if self.systable[sysnum]["handler"] != None:
                log.debug('Emulate syscall ' + self.systable[sysnum]["name"])
                return self.systable[sysnum]["handler"](*args) 
            else:
                log.warn('No support for syscall ' + self.systable[sysnum]["name"])
                return False
        else:
            log.warn('Unknown syscall ' + str(sysnum))
            return False

