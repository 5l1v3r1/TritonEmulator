#!/usr/bin/env python
# coding=utf-8

from emulator import *


def test1():
    emu = Emulator('./bin')
    emu.initialize()
    emu.set_input('A')

    pc = emu.getpc()
    while pc != 0x08048967:
        pc = emu.process()

    esp = emu.getreg('esp')
    buf = emu.getuint32(esp)


    dst = range(buf, buf + 4)
    value = map(ord, "1aaa")

    solver = InputSolver('./bin', pc)
    solver.set_input('A', emu.readcount)
    answer = solver.solveMemory(dst, value)
    print answer
    input1 = solver.createInput(answer)
    print input1

    open('input1', 'wb').write(input1)


def test2():
    emu = Debugger('./bin')
    emu.show_inst = True
    emu.initialize()
    
    seed = open('input1').read()
    emu.set_input(seed)

    pc = emu.getpc()
    while pc != 0x0804896C:
        pc = emu.process()

    solver = InputSolver('./bin', emu.readcount, pc, seed)
    answer = solver.solveRegister('eax', 110)
    print answer
    input1 = solver.createInput(answer)
    print input1

    open('input2', 'wb').write(input1) 


if __name__ == '__main__':
    test1()
    # test2()
