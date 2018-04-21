#!/usr/bin/env python
# coding=utf-8

"""
Module Name: Emulator.py
Create by  : Bluecake
Description: A tool for x86 and x86_64 program emulate
"""

from elftools.elf.elffile import ELFFile as ELF
import os, sys, stat 
from triton import TritonContext, ARCH, Instruction, MODE, CALLBACK, OPCODE, MemoryAccess
import tempfile
import subprocess
import lief
from pwn import context, asm
import string

# import self-defined class
from utils import *
from syscall import *



###############################################################################
#                        Instruction Exception                                #
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
###############################################################################
#                                  Main Class                                 #
###############################################################################
class Emulator(object):

    def __init__(self, binary, 
            dumpfile="", 
            show_inst=False, 
            show_output = True,
            symbolize=False, 
            isTaint=False, 
            log_level=logging.DEBUG):

        """
        Arguments:
            binary: path to executable binary 
        """

        self.binary = binary
        self.dumpfile = dumpfile
        self.show_inst = show_inst
        self.show_output = show_output
        self.running = True

        self.symbolize = symbolize
        self.isTaint = isTaint

        # list of read info, each member is a pair like (addr, length)
        self.read_record = []  
        # total length of read
        self.readcount = 0

        # list to control which byte should be symbolized or tainted
        self.symbolized = []
        self.taintable = []

        # root directory
        self.root = os.path.dirname(__file__)
        self.log_level = log_level
        self.log = get_logger("Emulator.py", log_level)

        elf = ELF(open(binary))
        self.arch = elf.get_machine_arch()
        
        SupportedArch = ['x86']
        if self.arch not in SupportedArch:
            raise UnsupportArchException(self.arch)
        
        if self.arch == 'x86':
            context.arch = 'i386'

        # Prepare syscall hooker
        self.syshook = Syscall(self.arch, log_level=self.log_level)

        self.memoryCache = list() 

        self.opcodeCacheFile = self.root + "/OpcodeCache.txt"
        if os.path.exists(self.opcodeCacheFile):
            with open(self.opcodeCacheFile) as f:
                self.opcodeCache = eval(f.read())
        else:
            self.opcodeCache = {}


    """
    Save opcodeCache to opcodeCacheFile
    """
    def __del__(self):

        with open(self.opcodeCacheFile, 'wb') as f:
            f.write(repr(self.opcodeCache))


    """
    Automatically take memory snapshot on the entrypoint of main()
    """
    def snapshot(self):

        if os.path.exists(self.dumpfile):
            return 

        os.chmod(self.binary, 0o777)
        _, debug_file = tempfile.mkstemp()
        peda_path = "/usr/share/peda/peda.py"
        type_path = self.root + '/type'
        with open(debug_file, 'w') as f:
            content = "source %s\nbreak _start\nstart\nnextcall\nadd-symbol-file %s 0\n%s\ncontinue\nfulldump %s\nquit\n"
            if self.arch == 'x86':
                breakpoint = "break * *(uint32_t)$esp"
            else:
                breakpoint = "break * *(uint64_t)$rsp"
            content = content % (peda_path, type_path, breakpoint, self.dumpfile)
            f.write(content)
            
        cmd = "gdb %s -nx -command=%s" % (self.binary, debug_file)
        self.log.info(cmd)
        # os.system(cmd)
        subprocess.check_output(cmd, shell=True)


    """
    Load binary file into memory
    """
    def loadBinary(self):
        Triton = self.triton
        binary = lief.parse(path)
        phdrs = binary.segments
        for phdr in phdrs:
            size = phdr.physical_size
            vaddr = phdr.virtual_address
            log.info('Loading 0x%06x - 0x%06x' % (vaddr, vaddr+size))
            Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
  

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
        for index in range(size):
            if not triton.isMemoryMapped(addr+index):
                addr_aligned = (addr + index) & (~0x7)
                for m in self.memoryCache:
                    if addr_aligned >= m['start'] and addr_aligned < m['start'] + m['size']:
                        mem_offset = addr_aligned - m['start']
                        value = m['memory'][mem_offset : mem_offset+8]
                        triton.setConcreteMemoryAreaValue(addr_aligned, value)
                        return
        return   


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
        else:
            raise UnsupportArchException(arch)

        # Define symbolic optimizations
        Triton.enableMode(MODE.ALIGNED_MEMORY, True)
        Triton.enableMode(MODE.ONLY_ON_SYMBOLIZED, True)

        # Define internal callbacks.
        Triton.addCallback(self.memoryCaching, CALLBACK.GET_CONCRETE_MEMORY_VALUE)
        
        if self.dumpfile == '':
            # get dumpfile from entry of main()
            self.dumpfile = '/tmp/dump.bin'
            self.snapshot()

        self.load_dump()


    """
    Retrieve current PC address
    """
    def getpc(self):
        if self.arch == 'x86':
            return self.getreg('eip')
        else:
            raise UnsupportArchException(self.arch)


    """
    Set new PC address
    """
    def setpc(self, value):
        if self.arch == 'x86':
            return self.setreg('eip', value)
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
            return (eax, ebx, ecx, edx)
        else:
            raise UnsupportArchException(self.arch)

    
    """
    Symbolizing input data
    """
    def symbolizing(self, addr, length, size=1):

        for i in range(0, length, size): 
            if addr + i in self.symbolized:
                # self.log.info("try to symbolize 0x%x" % (addr + i))
                print("try to symbolize 0x%x" % (addr + i))
                mem = MemoryAccess(addr + i, size)
                self.triton.convertMemoryToSymbolicVariable(mem)


    """
    Tainting input data
    """
    def tainting(self, addr, length):

        for i in range(length): 
            if addr + i in self.taintable:
                self.triton.taintMemory(addr + i)


    """
    Check whether target data is influenced
    """
    def isTainted(self, target):

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
                gadgets = ["mov eax, dword ptr [esi]", "mov dword ptr [edi], eax", "add esi, 4", "add edi, 4"]
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
                gadgets = ["mov al, byte ptr [esi]", "mov byte ptr [edi], al", "add esi, 1", "add edi, 1"]
                for gadget in gadgets:
                    instrument(gadget)
            instrument("pop eax")
            self.setpc(pc + instruction.getSize())
            return self.getpc()

        # Process
        self.triton.processing(instruction)
        if self.show_inst:
            print instruction, instruction.getType(), OPCODE.MOVSD

        if instruction.getType() in [OPCODE.SYSENTER, OPCODE.INT]:
            if not self.lastInstType not in [OPCODE.SYSENTER, OPCODE.INT]:
                sysnum, arg1, arg2, arg3 = self.getSyscallRegs()
                ret = self.syshook.syscall(sysnum, arg1, arg2, arg3, self)
                    
                """
                ret: Number (bytes of read), SYSCALL read
                     False, other SYSCALL
                """
                if type(ret) == int and ret > 0:

                    if self.symbolize:
                        self.symbolizing(arg2, ret)              
                    
                    if self.isTaint:
                        self.tainting(arg2, ret)

                    self.readcount += ret
                    self.read_record.append((arg2, ret))
                
            self.setpc(pc + instruction.getSize())

        elif instruction.getType() == OPCODE.HLT:
            self.log.info("Program stopped [call hlt]")
            exit(0)

        # Deal with instruction exception
        elif instruction.getType() == OPCODE.RET:
            new_pc = self.getpc()
            if not self.isValid(new_pc):
                self.lastInstType = instruction.getType()
                raise IllegalPcException(self.arch, new_pc)
        
        self.lastInstType = instruction.getType()
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
