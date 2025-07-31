
# Sample

```c++
#define LUCKY_LUO 0xfaceb00c

unsigned char* shellcode = (unsigned char*)0x100000;
STP_PRE_IMM(shellcode, fp, lr, sp, -16);
STP_PRE_IMM(shellcode, x0, x1, sp, -16);
STP_PRE_IMM(shellcode, x2, x3, sp, -16);
MOV_IMM(shellcode, x2, LUCKY_LUO);
MOV_IMM(shellcode, x3, 0x10002c); // real LR address
STP_PRE_IMM(shellcode, x2, x3, sp, -16);
MOV_IMM(shellcode, lr, LUCKY_LUO);
BR_REG(shellcode, x1);
ADD_IMM(shellcode, sp, sp, 16);
LDP_POST_IMM(shellcode, x2, x3, sp, 16);
LDP_POST_IMM(shellcode, x0, x1, sp, 16);
LDP_POST_IMM(shellcode, fp, lr, sp, 16);
MOV_IMM(shellcode, x1, 42);
STR_PRE_IMM(shellcode, x1, x0, 0);
RET(shellcode);
```