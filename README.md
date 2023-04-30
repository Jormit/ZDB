## ZDB
ZDB is a work in progress debugger for 64 bit elf binaries aiming to provide an experience similar to gdb. At the moment the debugger supports setting breakpoints and stepping, dissassembly with function and string info (via capstone) and showing the stack and the registers. Elf parsing extended on code from https://github.com/TheCodeArtist/elf-parser/blob/master/elf-parser.c to add .plt and .got address resolution.

## How To Use
This is only for linux and you must have capstone installed on your computer. See http://www.capstone-engine.org/. </br>
To compile run `make`. </br></br>
These are the currently supported commands.
```
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

int test() {
  return 1+1;
}

int main(void) {
  printf("Hello World!\n");
  puts("Hello\n");
  return test();
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
load-addr          size               section
0x0000000000000000 0x0000000000000000 
0x00000000004002a8 0x000000000000001c .interp
0x00000000004002c4 0x0000000000000024 .note.gnu.build-id
0x00000000004002e8 0x0000000000000020 .note.ABI-tag
0x0000000000400308 0x000000000000001c .gnu.hash
0x0000000000400328 0x0000000000000078 .dynsym
0x00000000004003a0 0x0000000000000044 .dynstr
0x00000000004003e4 0x000000000000000a .gnu.version
0x00000000004003f0 0x0000000000000020 .gnu.version_r
0x0000000000400410 0x0000000000000030 .rela.dyn
0x0000000000400440 0x0000000000000030 .rela.plt
0x0000000000401000 0x000000000000001b .init
0x0000000000401020 0x0000000000000030 .plt
0x0000000000401050 0x00000000000001b5 .text
0x0000000000401208 0x000000000000000d .fini
0x0000000000402000 0x0000000000000019 .rodata
0x000000000040201c 0x0000000000000044 .eh_frame_hdr
0x0000000000402060 0x0000000000000108 .eh_frame
0x0000000000403e10 0x0000000000000008 .init_array
0x0000000000403e18 0x0000000000000008 .fini_array
0x0000000000403e20 0x00000000000001d0 .dynamic
0x0000000000403ff0 0x0000000000000010 .got
0x0000000000404000 0x0000000000000028 .got.plt
0x0000000000404028 0x0000000000000010 .data
0x0000000000404038 0x0000000000000008 .bss
0x0000000000000000 0x000000000000004a .comment
0x0000000000000000 0x00000000000005e8 .symtab
0x0000000000000000 0x00000000000001e1 .strtab
0x0000000000000000 0x0000000000000103 .shstrtab
```

### Print Functions
```
[0x00000000]> func
[Regular Functions]
load-addr          name
0x0000000000401090 deregister_tm_clones
0x00000000004010c0 register_tm_clones
0x0000000000401100 __do_global_dtors_aux
0x0000000000401130 frame_dummy
0x0000000000401200 __libc_csu_fini
0x0000000000000000 puts@@GLIBC_2.2.5
0x0000000000401208 _fini
0x0000000000000000 printf@@GLIBC_2.2.5
0x0000000000000000 __libc_start_main@@GLIBC_2.2.5
0x0000000000401190 __libc_csu_init
0x0000000000401080 _dl_relocate_static_pie
0x0000000000401050 _start
0x0000000000401150 main
0x0000000000401000 _init
0x0000000000401140 test

[Dynamic Functions]
load-addr          name
0x0000000000000000 puts
0x0000000000000000 printf
0x0000000000000000 __libc_start_main
```

### Disassemble Functions
```
[0x00000000]> disas main
Disassembly of main
    0x401150:   push    rbp
    0x401151:   mov     rbp, rsp
    0x401154:   sub     rsp, 0x10
    0x401158:   mov     dword ptr [rbp - 4], 0
    0x40115f:   movabs  rdi, 0x402004 ;Hello World!
    0x401169:   mov     al, 0
    0x40116b:   call    0x401040
    0x401170:   movabs  rdi, 0x402012 ;Hello
    0x40117a:   mov     dword ptr [rbp - 8], eax
    0x40117d:   call    0x401030
    0x401182:   mov     dword ptr [rbp - 0xc], eax
    0x401185:   call    0x401140 <test>
    0x40118a:   add     rsp, 0x10
    0x40118e:   pop     rbp
    0x40118f:   ret
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
[0x401150]> regs
rax       0000000000401150
rbx       0000000000401190
rcx       0000000000401190
rdx       00007ffff34a59b8
rsp       00007ffff34a58b8
rbp       0000000000000000
rsi       00007ffff34a59a8
rdi       0000000000000001
r8        0000000000000000
r9        00007fcc010a1d60
r10       000000000000000b
r11       0000000000000002
r12       0000000000401050
r13       00007ffff34a59a0
r14       0000000000000000
r15       0000000000000000
rip       0000000000401150
```
### Inspect Stack
```
address         contents
0x7ffff53ee4f8  0x7f50bf824083 <-- $rsp
0x7ffff53ee500  0x7f50bfa2d620
0x7ffff53ee508  0x7ffff53ee5e8
0x7ffff53ee510  0x100000000
0x7ffff53ee518  0x401150
0x7ffff53ee520  0x401190
0x7ffff53ee528  0x321b7324b19689ae
0x7ffff53ee530  0x401050
0x7ffff53ee538  0x7ffff53ee5e0
0x7ffff53ee540  0x0
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
