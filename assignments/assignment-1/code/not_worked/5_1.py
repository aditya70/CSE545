#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babystack_level5

from pwn import *
import pwn

# Set up pwntools for the correct architecture
context.arch = 'amd64'
exe = context.binary = ELF(args.EXE or '/challenge/babystack_level5')
context.terminal = ["tmux", "splitw", "-h"]
# context.terminal = ["tmux", "splitw", "-v"]
# python3 template.py GDB

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
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

# r = process('/challenge/babystack_level5')

# pwn.gdb.attach(r)

r = start()
# r = process('/challenge/babystack_level5')

r.recvuntil(b"base pointer rbp: ")
bp = int(r.recvline(keepends=False), 16)

r.recvuntil(b"will be stored: ")
buf = int(r.recvline(keepends=False), 16)

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

# payload = b'A'*784

# r.sendline(payload)

r.interactive()

