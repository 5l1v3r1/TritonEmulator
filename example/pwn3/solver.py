#!/usr/bin/env python
# coding=utf-8

from emulator import *

emu = Emulator('./bin')
emu.initialize()
emu.set_input('A')

pc = emu.getpc()
while pc != 0x08048967:
    pc = emu.process()

src = emu.getSrc()
esp = emu.getreg('esp')
buf = emu.getuint32(esp)


dst = range(buf, buf + 8)
value = map(ord, "100aaaaa")

print src
print hex(pc)

solver = InputSolver('./bin', src, pc)
answer = solver.solveValue(dst, value)
print answer
input1 = solver.createInput(answer)
print input1

open('input1', 'wb').write(input1)


