# My Linux BootKit

## 1. Environment

    GRUB 0.97 + linux 2.6.18 i386

## 2. MBR 

1. Load Bootkit from disk to memory 0x80000
2. Jmp bootkit entry pointer (0x80000)

## 3. Bootkit

1. Restore old MBR to 0x7c00
2. Hook INT 13h
3. jmp old MBR

### 3.1. INT 13h Handler

1. Search `big_linux_boot` code from GRUB stage2 memory

        CODE: C1 EB 04 89 D8 83 C0 20
        c33: c1 eb 04           shrl	$4, %ebx     /* CS */
        c36: 89 d8              movl	%ebx, %eax
        c38: 83 c0 20           addl	$0x20, %eax  /* IP*/

2. hook `big_linux_boot` function

### 3.2. `big_linux_boot` Handler

1. Linux setup code loaded into 0x9000 and system code loaded into 0x100000 now.
2. Hook linux relocated entry pointer

        %000000000010007c ff e0                   jmp eax

### 3.3. Linux Relocated Handler

1. System run decompress kernel and jmp decompressed startup_32
2. We must search decompressed startup_32 address

        0010:007a76e8 31 db                   xor ebx, ebx
        0010:007a76ea ff e5                   jmp ebp
3. real startup_32 address in ebp, got it, and hook it

### 3.4. Decompressed Startup_32 Handler

1. linux image decompressed now.
2. We can controller all kernel memory, Juse for funy!!!
3. For example, hook `run_init_process`

        CODE：55 BD 0B 00 00 00 57 89 C7 56
        %00000000c04011f0 55                      push ebp
        %00000000c04011f1 bd 0b 00 00 00          mov ebp, 00000000bh
        %00000000c04011f6 57                      push edi
        %00000000c04011f7 89 c7                   mov edi, eax
        %00000000c04011f9 56                      push esi

