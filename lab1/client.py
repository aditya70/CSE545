from pwn import process

def main():
	r = process("./server.py")
	r.sendline("hello")
	line = r.recvline()
	print(line)

if __name__ == "__main__":
	main()