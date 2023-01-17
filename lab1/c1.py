from pwn import remote

def main():
    #r = process("./service")
    r = remote("107.21.135.41", 2222)

    r.recvuntil(b"menu: ")
    r.sendline(b"1")

    for x in range(100):
        line = r.recvuntil(b"? ")
        print(line)
        words = line.split()
        a = int(words[4])
        b = int(words[6][:-1])
        print("a: %d b: %d" %(a, b))
        c = a + b
        print(" Sum:", c)
        r.sendline(b"%d" %c)

    r.recvuntil(b"ID: ")    
    r.sendline(b"agoyal61")
    r.close()    

if __name__ == "__main__":
	main()        
