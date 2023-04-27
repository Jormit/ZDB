## ZDB
ZDB is a work in progress debugger for 64 bit elf binaries aiming to provide an experience similar to gdb. At the moment the debugger supports setting breakpoints and stepping, dissassembly with function and string info (via capstone) and showing the stack and the registers. Elf parsing extended on code from https://github.com/TheCodeArtist/elf-parser/blob/master/elf-parser.c to add .plt and .got address resolution.

## How To Use
This is only for linux and you must have capstone installed on your computer. See http://www.capstone-engine.org/. </br>
To compile run `make`. </br></br>
These are the currently supported commands.
```
Commands:
r                 - starts/restarts execution.
c                 - continues execution until end or breakpoint.
b [addr/func]     - sets break at specified address.
breaks            - shows set breakpoints.
stack [amount]    - displays stackdump of [amount] length.
regs              - displays register values.
sect              - displays elf sections.
func              - displays binary functions.
disas [func/addr] - displays disassembly of specified area.
hex [func/addr]   - displays hexdump of specified area.
q                 - quits program.
```

## Example
### Program to Debug (test.c)
```C
#include <stdio.h>

int main(void){
	printf("Hello World!\n");
	return 1;
}
```
### Running ZDB
```
./debugger test
        _ _
       | | |
 ______| | |__
|_  / _` | '_ \
 / / (_| | |_) |
/___\__,_|_.__/
Type "help" for more info.
[0x00000000]>
```
### Print Sections
```
[0x00000000]> sect
load-addr  size       section
0x00000000 0x00000000 |
0x004002a8 0x0000001c | .interp
0x004002c4 0x00000024 | .note.gnu.build-id
0x004002e8 0x00000020 | .note.ABI-tag
0x00400308 0x0000001c | .gnu.hash
0x00400328 0x00000060 | .dynsym
0x00400388 0x0000003f | .dynstr
0x004003c8 0x00000008 | .gnu.version
0x004003d0 0x00000020 | .gnu.version_r
0x004003f0 0x00000030 | .rela.dyn
0x00400420 0x00000018 | .rela.plt
0x00401000 0x0000001b | .init
0x00401020 0x00000020 | .plt
0x00401040 0x00000195 | .text
0x004011d8 0x0000000d | .fini
0x00402000 0x00000012 | .rodata
0x00402014 0x0000003c | .eh_frame_hdr
0x00402050 0x000000e8 | .eh_frame
0x00403e10 0x00000008 | .init_array
0x00403e18 0x00000008 | .fini_array
0x00403e20 0x000001d0 | .dynamic
0x00403ff0 0x00000010 | .got
0x00404000 0x00000020 | .got.plt
0x00404020 0x00000010 | .data
0x00404030 0x00000008 | .bss
0x00000000 0x0000004a | .comment
0x00000000 0x000005b8 | .symtab
0x00000000 0x000001ca | .strtab
0x00000000 0x00000103 | .shstrtab
```

### Print Functions
```
[0x00000000]> func
[Dynamic Functions]
.got       .plt         symbol_name
0x00404018 0x00401030 | printf

[User Defined Functions]
address      symbol_name
0x00401080 | deregister_tm_clones
0x004010b0 | register_tm_clones
0x004010f0 | __do_global_dtors_aux
0x00401120 | frame_dummy
0x004011d0 | __libc_csu_fini
0x004011d8 | _fini
0x00401160 | __libc_csu_init
0x00401070 | _dl_relocate_static_pie
0x00401040 | _start
0x00401130 | main
0x00401000 | _init
```

### Disassemble Functions
```
[0x00000000]> disas main
Disassembly of main
    0x401130:   push    rbp
    0x401131:   mov     rbp, rsp
    0x401134:   sub     rsp, 0x10
    0x401138:   mov     dword ptr [rbp - 4], 0
    0x40113f:   movabs  rdi, 0x402004 ;Hello World!
    0x401149:   mov     al, 0
    0x40114b:   call    0x401030 <printf>
    0x401150:   xor     ecx, ecx
    0x401152:   mov     dword ptr [rbp - 8], eax
    0x401155:   mov     eax, ecx
    0x401157:   add     rsp, 0x10
    0x40115b:   pop     rbp
    0x40115c:   ret
```

### Set Breakpoints
```
[0x00000000]> b main
[!] Break set at 0x401130
[0x00000000]> b 0x40114b
[!] Break set at 0x40114b
[0x00000000]> breaks
1: 0x401130
2: 0x40114b
```
### Execute Until Breakpoint
```
[0x00000000]> b main
[!] Break set at 0x401130
[0x00000000]> r
[!] Breakpoint 1 hit.
```
### Inspect Registers
```
[0x401130]> regs
rax:  401130
rbx:  401160
rcx:  401160
rdx:  7fffd1577b78
rsp:  7fffd1577a78
rbp:  0
rsi:  7fffd1577b68
rdi:  1
rip:  401130
r8 :  0
r9 :  7f36cc021d60
r10:  b
r11:  2
r12:  401040
r13:  7fffd1577b60
r14:  0
r15:  0
```
### Inspect Stack
```
[0x401130]> stack 10
0x7fffd1577a78 | 0x7f36cbe34083 <-- $rsp
0x7fffd1577a80 | 0x7f36cc03d620
0x7fffd1577a88 | 0x7fffd1577b68
0x7fffd1577a90 | 0x100000000
0x7fffd1577a98 | 0x401130
0x7fffd1577aa0 | 0x401160
0x7fffd1577aa8 | 0xf081d1a9085dbfaf
0x7fffd1577ab0 | 0x401040
0x7fffd1577ab8 | 0x7fffd1577b60
0x7fffd1577ac0 | 0x0
```
### Inspect Memory
```
[0x401130]> hex 0x402004
0000000000402004: 4865 6c6c 6f20 576f 726c 6421 0a00 0000 Hello World!....
0000000000402014: 011b 033b 3800 0000 0600 0000 0cf0 ffff ...;8...........
0000000000402024: 7c00 0000 2cf0 ffff 5400 0000 5cf0 ffff |...,...T...\...
0000000000402034: 6800 0000 1cf1 ffff a400 0000 4cf1 ffff h...........L...
0000000000402044: c400 0000 bcf1 ffff 0c01 0000 1400 0000 ................
0000000000402054: 0000 0000 017a 5200 0178 1001 1b0c 0708 .....zR..x......
0000000000402064: 9001 0000 1000 0000 1c00 0000 d0ef ffff ................
0000000000402074: 2f00 0000 0044 0710 1000 0000 3000 0000 /....D......0...
```
