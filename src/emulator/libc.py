#!/bin/python

"""
Module Name: Libc Hooker
Create by  : Bluecake
Description: Provide handlers for libc functions
"""

from utils import *


def getFormatString(addr):
    replaceTable = {
            "%s": "{}", "%d": "{:d}","%#02x": "{:#02x}",
            "%#x": "{:#x}", "%x": "{:x}", "%02X": "{:02x}",
            "%c": "{:c}", "%02x": "{:2x}", "%ld": "{:d}",
            "%*s": "", "%lX": "{:x}", "%08x": "{:08x}",
            "%u": "{:d}"
            }
    oriFormat = getMemoryString(addr)
    for key, value in replaceTable.items():
        oriFormat = oriFormat.replace(key, value)
    return oriFormat


# Simulate the printf function
def printfHandler():
    log.info('printf hook successfully')

    # Get arguments
    arg1 = getFormatString(Triton.getConcreteRegisterValue(Triton.registers.rdi))
    arg2 = Triton.getConcreteRegisterValue(Triton.registers.rsi)
    arg3 = Triton.getConcreteRegisterValue(Triton.registers.rdx)
    arg4 = Triton.getConcreteRegisterValue(Triton.registers.rcx)
    arg5 = Triton.getConcreteRegisterValue(Triton.registers.r8)
    arg6 = Triton.getConcreteRegisterValue(Triton.registers.r9)
    nbArgs = arg1.count('{')
    args = [arg2, arg3, arg4, arg5, arg6][:nbArgs]
    s = arg1.format(*args)
    sys.stdout.write(s)
    return 0


def readHandler():
    log.info('read hook successfully')

    # Get arguments
    fd = Triton.getConcreteRegisterValue(Triton.registers.rdi)
    buf = Triton.getConcreteRegisterValue(Triton.registers.rsi)
    size = Triton.getConcreteRegisterValue(Triton.registers.rdx)

    #read_result = os.read(fd, size) + "\0"
    read_result = 'aaaabaaa'
    Triton.setConcreteMemoryAreaValue(buf, read_result)

    # Symblize input
    for i in xrange(len(read_result)):
    #for i in xrange(120, 136):
        mem = MemoryAccess(buf + i, CPUSIZE.BYTE)
        Triton.convertMemoryToSymbolicVariable(mem)

    return len(read_result)
        

def exitHandler():
    log.info('exit hook successfully')
    sys.exit()


def libcMainHandler():
    log.info('__libc_start_main hook successfully')

    # Get arguments
    main = Triton.getConcreteRegisterValue(Triton.registers.rdi)

    # push the return value to jump into the main() function
    Triton.concretizeRegister(Triton.registers.rsp)
    Triton.setConcreteRegisterValue(Triton.registers.rsp, Triton.getConcreteRegisterValue(Triton.registers.rsp) - CPUSIZE.QWORD)

    ret2main = MemoryAccess(Triton.getConcreteRegisterValue(Triton.registers.rsp), CPUSIZE.QWORD)
    Triton.concretizeMemory(ret2main)
    Triton.setConcreteMemoryValue(ret2main, main)

    # Setup argc / argv
    Triton.concretizeRegister(Triton.registers.rdi)
    Triton.concretizeRegister(Triton.registers.rsi)

    argvs = sys.argv[2:] 

    # Define argc / argv
    base = StackBottom - 0x1000
    addrs = []

    for argv in argvs:
        addrs.append(base)
        Triton.setConcreteMemoryAreaValue(base, argv+"\x00")
        base += len(argv)+1

    argc = len(argvs)
    argv = base
    for addr in addrs:
        Triton.setConcreteMemoryValue(MemoryAccess(base, CPUSIZE.QWORD), addr)
        base += CPUSIZE.QWORD

    Triton.setConcreteRegisterValue(Triton.registers.rdi, argc)
    Triton.setConcreteRegisterValue(Triton.registers.rsi, argv)
    return 1


hookTable = {
        "printf": (printfHandler, 0x10000000),
        "read": (readHandler, 0x10000001),
        "exit": (exitHandler, 0x10000002),
        "__libc_start_main": (libcMainHandler, 0x10000003)
        }

addr2Handler = {}
for key, value in hookTable.items():
    addr2Handler[value[1]] = value[0]  


def hookingHandler():
    pc = getPC()
    if addr2Handler.has_key(pc):
        # call hook handler
        ret_value = addr2Handler[pc]()

        Triton.concretizeRegister(Triton.registers.rax)
        Triton.setConcreteRegisterValue(Triton.registers.rax, ret_value)

        # Get return address
        ret_addr = Triton.getConcreteMemoryValue(MemoryAccess(Triton.getConcreteRegisterValue(Triton.registers.rsp), CPUSIZE.QWORD))

        # Hijack RIP to skip the call
        Triton.concretizeRegister(Triton.registers.rip)
        Triton.setConcreteRegisterValue(Triton.registers.rip, ret_addr)

        # Restore RSP (simulate the ret instruction)
        Triton.concretizeRegister(Triton.registers.rsp)
        Triton.setConcreteRegisterValue(Triton.registers.rsp, Triton.getConcreteRegisterValue(Triton.registers.rsp)+CPUSIZE.QWORD)

    return

def hookLibc(binary):
    # hook function call by replace plt address
    for rel in binary.pltgot_relocations:
        symbolName = rel.symbol.name
        symbolRelo = rel.address
        log.debug('try to hook ' + symbolName)
        if hookTable.has_key(symbolName):
            log.info("hooking " + symbolName)
            Triton.setConcreteMemoryValue(MemoryAccess(symbolRelo, CPUSIZE.QWORD), hookTable[symbolName][1])
