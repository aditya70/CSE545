#from pwn import process
from pwn import remote

def main():
	#r = process("./server.py")
	r = remote("localhost", 6000)
	r.sendline("hello")
	line = r.recvline()
	print(line)

	r.close()

if __name__ == "__main__":
	main()