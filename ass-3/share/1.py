
def malloc(p, size, content):
    p.recvuntil( b"Choice:")
    p.sendline(b"1")
    p.recvuntil(b"chunk?:")
    p.sendline(b"%d" %size)
    p.sendline(b"%d" %content)

def free(p, index):
    p.recvuntil( b"Choice:")
    p.sendline(b"3")
    p.recvuntil(b"Index:")
    p.sendline(b"%d" %index)

def edit(p, index, content):
    p.recvuntil( b"Choice:")
    p.sendline(b"2")
    p.recvuntil(b"Index:") 
    p.sendline(b"%d" %index)
    p.recvuntil(b"New content:")
    p.sendline(b"%b" %content)

def exit(p):
    p.recvuntil( b"Choice:")
    p.sendline(b"6")

def check(p):
    p.recvuntil( b"Choice:")
    p.sendline(b"5")