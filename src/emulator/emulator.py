#!/usr/bin/env python
# coding=utf-8

"""
Module Name: Emulator.py
Create by  : Bluecake
Description: A tool for x86 and x86_64 program emulate
"""

import os, sys, stat 
from triton import * 
import tempfile
import subprocess
import lief
from pwn import *
import string
import hashlib

# import self-defined class
from utils import *
from syscall import *



###############################################################################
#                          Emulation Exception                                #
###############################################################################
class IllegalPcException(Exception):
    def __init__(self, arch, pc):
        if arch == 'x86':
            Exception.__init__(self, "Eip address [0x%x] is illegal" % pc)
        else:
            raise UnsupportArchException(arch)


class IllegalInstException(Exception):
    def __init__(self, arch, pc):
        if arch == 'x86':
            Exception.__init__(self, "Instruction at [0x%x] is illegal" % pc)
        else:
            raise UnsupportArchException(arch)


class InfinityLoopException(Exception):
    def __init__(self, arch, pc):
        if arch == 'x86':
            Exception.__init__(self, "Encounter inifinity instruction at 0x%x" % pc)
        else:
            raise UnsupportArchException(arch)


class MemoryAccessException(Exception):
    def __init__(self, pc, addr):
        Exception.__init__(self, "Invalid memory [0x%x] access instruction at 0x%x" % (addr, pc))

############################################################################### 
#                                  Main Class                                 #
###############################################################################
class Emulator(object):

    def __init__(self, binary, dumpfile="", log_level=logging.DEBUG):

        """
        Arguments:
            binary:      path of executable binary 
            dumpfile:    path of memory snapshot file
        """

        self.binary = binary
        self.dumpfile = dumpfile
        self.show_inst = True
        self.show_output = True
        self.symbolize = False
        self.isTaint = False

        # total length of read
        self.readcount = 0

        # list to control which byte should be symbolized or tainted
        self.symbolize_list = []
        self.taint_list = []

        # root directory
        self.root = os.path.dirname(__file__)
        self.log_level = log_level
        self.log = get_logger("Emulator.py", log_level)

        elf = ELF(binary)
        if elf.get_machine_arch() in ['x86', 'i386']:
            self.arch = 'x86'
        elif elf.get_machine_arch() in ['x64', 'amd64']:
            self.arch = 'x64'

        SupportedArch = ['x86', 'x64']
        if self.arch not in SupportedArch:
            raise UnsupportArchException(self.arch)
        
        if self.arch == 'x86':
            context.arch = 'i386'
        else:
            context.arch = 'amd64'

        # Prepare syscall hooker
        self.syshook = Syscall(self.arch, log_level=self.log_level)

        self.memoryCache = list() 

        self.opcodeCacheUpdate = False
        self.opcodeCacheFile = self.root + "/OpcodeCache.txt"
        if os.path.exists(self.opcodeCacheFile):
            with open(self.opcodeCacheFile) as f:
                self.opcodeCache = eval(f.read())
        else:
            self.opcodeCache = {}

        self.memAccessCheck = True

        self.running = True
        self.SyscallFail = False
        # last pc address
        self.last_pc = 0
        self.inst_count = 0


    """
    Save opcodeCache to opcodeCacheFile
    """
    def __del__(self):

        if self.opcodeCacheUpdate:
            with open(self.opcodeCacheFile, 'wb') as f:
                f.write(repr(self.opcodeCache))


    """
    Automatically take memory snapshot on the entrypoint of main()
    TODO: Add snapshot at any pc address
    """
    def snapshot(self):

        if os.path.exists(self.dumpfile):
            return 

        os.chmod(self.binary, 0o777)
        _, debug_file = tempfile.mkstemp()
        peda_path = "/usr/share/peda/peda.py"
        type_path = self.root + '/type'
        elf = lief.parse(self.binary) 

        with open(debug_file, 'w') as f:
            content = "source %s\n" \
                    "break * 0x%x\n" \
                    "start\n" \
                    "nextcall\n" \
                    "add-symbol-file %s 0\n%s\n" \
                    "continue\nfulldump %s\n" \
                    "quit\n"
            if self.arch == 'x86':
                breakpoint = "break * *(uint32_t)$esp"

            else:
                breakpoint = "break * $rdi"

            content = content % (peda_path, elf.entrypoint, type_path, breakpoint, self.dumpfile)
            f.write(content)
            
        cmd = "gdb %s -nx -command=%s" % (self.binary, debug_file)
        self.log.info(cmd)
        # os.system(cmd)
        subprocess.check_output(cmd, shell=True)

    
    """
    Add a virtual segment
    """
    def add_segment(self, start, size, content=''):

        self.memoryCache.append({
                "start" : start,
                "size"  : size,
            })
        
        if len(content) > 0:
            self.writeMemory(start, content)


    """
    Deal with program output
    """
    def write(self, fd, content):

        if self.show_output:
            os.write(fd, content)


    """
    Load binary file into memory
    """
    def load_binary(self):

        self.triton = TritonContext()
        Triton = self.triton

        if self.arch == 'x86':

            Triton.setArchitecture(ARCH.X86)
            stack = {
                'start': 0xffff0000, 
                'size' : 0x8000,
                'memory' : '\x00' * 0x8000}
            self.memoryCache.append(stack)

            fake_esp = stack['start'] + stack['size'] - 0x1000
            self.setreg('esp', fake_esp)

        elif self.arch == 'x64':

            Triton.setArchitecture(ARCH.X86_64)
            stack = {
                'start': 0xffffffffffff0000, 
                'size' : 0x8000}
            self.memoryCache.append(stack)

            fake_rsp = stack['start'] + stack['size'] - 0x1000
            self.setreg('rsp', fake_rsp)

        else:
            raise UnsupportArchException(self.arch)
        
        Triton.setConcreteMemoryAreaValue(stack['start'], '\x00' * stack['size'])

        # Define symbolic optimizations
        Triton.enableMode(MODE.ALIGNED_MEMORY, True)
        Triton.enableMode(MODE.ONLY_ON_SYMBOLIZED, True)

        # Define internal callbacks.
        if self.memAccessCheck:
            Triton.addCallback(self.accessValidate, CALLBACK.GET_CONCRETE_MEMORY_VALUE)

        elf = lief.parse(self.binary)
        phdrs = elf.segments
        for phdr in phdrs:

            size = phdr.physical_size
            vaddr = phdr.virtual_address

            if size <= 0:
                continue

            self.log.debug('Loading 0x%06x - 0x%06x' % (vaddr, vaddr+size))
            Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
            self.memoryCache.append({
                    'start': phdr.virtual_address,
                    'size' : phdr.physical_size,
                })
        
        self.setpc(elf.entrypoint)
  

    """
    Set targeted register
    """
    def setreg(self, reg, value):
        Triton = self.triton
        return eval('Triton.setConcreteRegisterValue(Triton.registers.%s, %d)' % (reg, value))


    """
    Retrieve targetd register
    """
    def getreg(self, reg):
        Triton = self.triton
        return eval('Triton.getConcreteRegisterValue(Triton.registers.%s)' % (reg,))


    """
    Retreive return value which is usually stored in register eax[rax]
    """
    def getret(self):

        if self.arch == 'x86':
            return self.getreg('eax')

        elif self.arch == 'x64':
            return self.getreg('rax')

        else:
            raise UnsupportArchException(self.arch)


    """
    Retrieve string terminated with null byte
    """
    def getMemoryString(self, addr):
        Triton = self.triton

        s = ""
        index = 0
        while Triton.getConcreteMemoryValue(addr + index):
            c = chr(Triton.getConcreteMemoryValue(addr + index))
            if c not in string.printable: 
                break
            s += c
            index += 1
        return s


    """
    Retrieve a block of data 
    """
    def getMemory(self, addr, size):
        Triton = self.triton
        s = Triton.getConcreteMemoryAreaValue(addr, size)
        return s

    
    """
    Write data into memory
    """
    def writeMemory(self, addr, content):

        # print 'write 0x%x with %s' % (addr, str(content))
        # connectPycharm('10.2.111.189')
        if type(content) == int or type(content) == long:

            if self.arch == 'x86':
                mem = MemoryAccess(addr, 4)

                if not self.triton.isMemoryMapped(addr):
                    self.triton.getConcreteMemoryValue(mem)

                self.triton.setConcreteMemoryValue(mem, content)

            elif self.arch == 'x64':
                mem = MemoryAccess(addr, 8)

                if not self.triton.isMemoryMapped(addr):
                    self.triton.getConcreteMemoryValue(mem)

                self.triton.setConcreteMemoryValue(mem, content)

        else:
            mem = MemoryAccess(addr, 0x40)
            if not self.triton.isMemoryMapped(addr):
                self.triton.getConcreteMemoryValue(mem)
            self.triton.setConcreteMemoryAreaValue(addr, content)


    """
    Retrieve uint8
    """
    def getuint8(self, addr):
        mem = MemoryAccess(addr, 1)
        self.triton.concretizeMemory(mem)
        return self.triton.getConcreteMemoryValue(mem)


    """
    Retrieve uint16
    """
    def getuint16(self, addr):
        mem = MemoryAccess(addr, 2)
        self.triton.concretizeMemory(mem)
        return self.triton.getConcreteMemoryValue(mem)


    """
    Retrieve uint32
    """
    def getuint32(self, addr):
        mem = MemoryAccess(addr, 4)
        self.triton.concretizeMemory(mem)
        return self.triton.getConcreteMemoryValue(mem)


    """
    Retrieve uint64
    """
    def getuint64(self, addr):
        mem = MemoryAccess(addr, 8)
        self.triton.concretizeMemory(mem)
        return self.triton.getConcreteMemoryValue(mem)


    """
    Recover memory, registers with dumpfile
    """
    def load_dump(self):
        Triton = self.triton
        log = self.log

        # Open the dump
        fd = open(self.dumpfile)
        data = eval(fd.read())
        fd.close()

        # Extract registers and memory
        regs = data[0]
        mems = data[1]
        gs_8 = data[2]

        context.arch = 'i386'

        # Load memory into memoryCache
        log.debug('Define memory areas')
        for mem in mems:
            start = mem['start']
            end   = mem['end']
            log.debug('Memory caching %x-%x' %(start, end))
            if mem['memory']:
                self.memoryCache.append({
                    'start':  start,
                    'size':   end - start,
                    'memory': mem['memory'],
                })

        # Make sure to restore gs register first
        from pwn import u32
        self.setreg('gs', regs['gs'])
        for i in range(7):
            log.debug('Restore gs[0x%x]' % (i*4))
            v = u32(self.getMemory(gs_8 + i*4, 4))
            write_gs = ['mov eax, %s' % hex(v), 'mov gs:[%d], eax' % (i*4)]
            for inst in write_gs:
                asm_code = asm(inst)
                instruction = Instruction()
                instruction.setOpcode(asm_code)
                instruction.setAddress(0)
                Triton.processing(instruction)

        # Load registers into the triton
        log.debug('Define registers')
        for reg, value in regs.items():
            log.debug('Load register ' + reg)
            self.setreg(reg, value)

        return       


    """
    MemoryCache just speed up the procedure of load_dump
    """
    def memoryCaching(self, triton, mem):

        addr = mem.getAddress()
        size = mem.getSize()
        # print "memoryCache is called", hex(addr), hex(size)
        for index in range(size):
            if not triton.isMemoryMapped(addr, size):
                for m in self.memoryCache:
                    if addr >= m['start'] and addr + size < m['start'] + m['size']:
                        offset = addr - m['start']
                        value = m['memory'][offset : offset + size]
                        triton.setConcreteMemoryAreaValue(addr, value)
                        return
        return   

    
    """
    Callback: Validate address when memory access occurs
    """
    def accessValidate(self, triton, mem):

        addr = mem.getAddress()
        size = mem.getSize()
        for index in range(size):
            for m in self.memoryCache:
                if addr >= m['start'] and addr + size < m['start'] + m['size']:
                    return

        if triton.getArchitecture() == ARCH.X86:
            pc = triton.getConcreteRegisterValue(triton.registers.eip)
            raise MemoryAccessException(pc, addr)
        else:
            raise UnsupportArchException(str(ARCH.X86_64))


    """
    Switch to checking memory access address
    """
    def checkAccess(self, switch):
        """
        Argument:
            switch: boolean, 
                    if True, do access check,
                    if False, do nothing
        """
        self.memAccessCheck = switch


    """
    Check whether a specific address is a valid address
    """
    def isValid(self, addr):

        for m in self.memoryCache:
            if addr >= m['start'] and addr < m['start'] + m['size']:
                return True
        return False 


    """
    Prepare everything before starting emulate
    """
    def initialize(self):

        self.triton = TritonContext()
        Triton = self.triton

        if self.arch == 'x86':
            Triton.setArchitecture(ARCH.X86)
        elif self.arch == 'x64':
            Triton.setArchitecture(ARCH.X86_64)
        else:
            raise UnsupportArchException(self.arch)

        # Define symbolic optimizations
        Triton.enableMode(MODE.ALIGNED_MEMORY, True)
        Triton.enableMode(MODE.ONLY_ON_SYMBOLIZED, True)

        # Define internal callbacks.
        Triton.addCallback(self.memoryCaching, CALLBACK.GET_CONCRETE_MEMORY_VALUE)
        
        if self.dumpfile == '':
            file_hash = md5(self.binary)            
            # get dumpfile from entry of main()
            self.dumpfile = '/tmp/%s_%s_dump.bin' % (os.path.basename(self.binary), file_hash)
            self.snapshot()

        self.load_dump()
        self.lastInstType = OPCODE.CALL

    """
    Retrieve current PC address
    """
    def getpc(self):
        if self.arch == 'x86':
            return self.getreg('eip')

        elif self.arch == 'x64':
            return self.getreg('rip')

        else:
            raise UnsupportArchException(self.arch)


    """
    Set new PC address
    """
    def setpc(self, value):
        if self.arch == 'x86':
            return self.setreg('eip', value)

        elif self.arch == 'x64':
            return self.setreg('rip', value)

        else:
            raise UnsupportArchException(self.arch)

    """
    Retrieve registers related to syscall
    If arch is x86, return eax, ebx, ecx, edx
    """
    def getSyscallRegs(self):
        if self.arch == 'x86':
            eax = self.getreg('eax')
            ebx = self.getreg('ebx')
            ecx = self.getreg('ecx')
            edx = self.getreg('edx')
            esi = self.getreg('esi')
            edi = self.getreg('edi')
            ebp = self.getreg('ebp')
            return eax, ebx, ecx, edx, esi, edi, ebp
        else:
            raise UnsupportArchException(self.arch)

    
    """
    
    """
    def set_input(self, data):

        if hasattr(self, 'stdin'):
            self.stdin += data
        else:
            self.stdin = data
            

    """
    Retrun total length of input bytes
    """
    def getInputLen(self):

        return self.readcount

    
    """
    Symbolizing input data
    """
    def symbolizing(self, addr, length, size=1):

        for i in range(0, length, size): 
            if self.readcount + i in self.symbolize_list or hasattr(self, 'ForceSymbolize'):

                self.log.debug("try to symbolize 0x%x" % (addr + i))
                mem = MemoryAccess(addr + i, size)
                self.triton.convertMemoryToSymbolicVariable(mem)


    """
    Tainting input data
    """
    def tainting(self, addr, length):
        
        for i in range(length): 
            if self.readcount + i in self.taint_list:
                # title('tainting', i)
                self.triton.taintMemory(addr + i)


    """
    Check whether target data is influenced
    @param target: memory address list or register
    """
    def isTainted(self, target):

        if type(target) == type(self.triton.registers.eax):
            return isRegisterTainted(target)

        else:
            for aByte in target:
                if self.triton.isMemoryTainted(aByte):
                    return True

        return False

   
    """
    Process only an instruction
    """
    def process(self):

        if not self.running:
            return False
        
        pc = self.getpc()

        if not self.isValid(pc):
            self.running = False
            return False

        self.inst_count += 1

        if pc == self.last_pc:
            self.inst_loop += 1
            """
            When encounter unsupported instruction, 
                the program might have got stuck.
            """
            if self.show_inst >= 100:
                raise InfinityLoopException(self.arch)
        else:
            self.inst_loop = 0

        opcode = self.getMemory(pc, 16)

        # Create the Triton instruction
        instruction = Instruction()
        instruction.setOpcode(bytes(opcode))
        instruction.setAddress(pc)
        
        Triton = self.triton
        Triton.disassembly(instruction)
        
        
        inst = Instruction()
        def instrument(opcode):

            if not self.opcodeCache.has_key(opcode):
                bincode = asm(opcode)
                inst.setOpcode(bincode)
                inst.setAddress(0)
                Triton.processing(inst)
                self.opcodeCache[opcode] = bincode
                self.opcodeCacheUpdate = True

            else:
                inst.setOpcode(self.opcodeCache[opcode])
                inst.setAddress(0)
                Triton.processing(inst)

        if instruction.getType() == OPCODE.MOVSD: 

            """
            For unknown reason, triton didn't work when meet repeat mov 
            So I did some patch by hand
            """
            ecx = self.getreg('ecx')
            instrument("push eax")
            self.log.debug('try to patch "rep movsd"')

            for i in range(ecx):
                gadgets = ["mov eax, dword ptr [esi]", "mov dword ptr [edi], eax", 
                        "add esi, 4", "add edi, 4"]
                for gadget in gadgets:
                    instrument(gadget)

            instrument("pop eax")
            self.setpc(pc + instruction.getSize())

            return self.getpc()

        elif instruction.getType() == OPCODE.MOVSB:

            self.log.debug('try to patch "rep movsb"')
            ecx = self.getreg('ecx')
            instrument("push eax")
            for i in range(ecx):
                gadgets = ["mov al, byte ptr [esi]", "mov byte ptr [edi], al", 
                        "add esi, 1", "add edi, 1"]
                for gadget in gadgets:
                    instrument(gadget)
            instrument("pop eax")
            self.setpc(pc + instruction.getSize())
            return self.getpc()

        # Process
        self.triton.processing(instruction)
        if self.show_inst:
            print instruction

        if instruction.getType() in [OPCODE.SYSENTER, OPCODE.INT]:

            if not self.lastInstType not in [OPCODE.SYSENTER, OPCODE.INT]:

                sysnum, arg1, arg2, arg3, arg4, arg5, arg6 = self.getSyscallRegs()
                """
                example: (syscall_ret, "read"), SYSCALL read
                """
                ret, systype = self.syshook.syscall(sysnum, arg1, arg2, arg3, 
                        arg4, arg5, arg6, self)

                if systype == 'read' and ret > 0:

                    if self.symbolize:
                        self.symbolizing(arg2, ret)              
                    
                    if self.isTaint:
                        self.tainting(arg2, ret)
                    
                    # title('ret', ret)
                    # title('readcount', self.readcount)
                    self.readcount += ret

                elif ret == False:
                    self.SyscallFail = True

                
            self.setpc(pc + instruction.getSize())

        elif instruction.getType() == OPCODE.HLT:
            self.log.info("Program stopped [call hlt]")
            self.running = False
            self.setpc(0)

        # Deal with instruction exception
        elif instruction.getType() == OPCODE.RET:
            new_pc = self.getpc()
            if not self.isValid(new_pc):
                self.lastInstType = instruction.getType()
                raise IllegalPcException(self.arch, new_pc)
        
        self.lastInstType = instruction.getType()
        self.last_pc = pc
        pc = self.getpc()
        return pc


    """
    Ok, everything is prepared, just go
    """
    def start(self):
        self.initialize()

        self.log.info("Start emulation")

        pc = self.getpc()
        self.lastInstType = None
        
        while pc:    
            pc = self.process()

        self.log.info("Emulation done")
        return
