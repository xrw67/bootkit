; mbr.asm 
; Copy bootkit to 0x80000 and jmp it

; in 16 bit read mode

	bits 16

	org 0x7c00

; The stack segment
%define STACKSEG		0x2000
; Loader code segment
%define BOOTKIT_SEGMENT	0x8000

; start is loaded at 0x7c00 and is jumped to with CS:IP 0:0x7c00
start:
	jmp after_param
	times 4 - ($-$$) nop

;================================================
; 参数，位于+4偏移处，以下内容要bootkit安装程序来填写
;================================================
mbr_param:
	mbr_magic: db "BKS1" ; BootKit Stage 1
	bootkit_dap: 
	    db 0x10, 0x00		; size & unused
		dw 0x00			; num_sectors
		dw 0x00			; dst_offset 
		dw BOOTKIT_SEGMENT	; dst_segment
		dq 0x00			; src_lba_addr

after_param:
	cli
	; set up %ds and %ss as offset from 0
	xor	ax, ax
	mov	ds, ax
	mov	ss, ax
	mov sp, STACKSEG ; set temp stack
	sti

	; load bootkit from disk
	mov si, bootkit_dap ; DS:SI = Data Accesss Packet
	mov ax, 0x4280      ; AH=42h, AL=80h
	int 0x13
	jc die
	
	; jmp to bootkit
	push word BOOTKIT_SEGMENT
	push word 0x0200
	retf
	
die:
	; Allow the user to press a key, then reboot
	xor	ax, ax
	int	0x16
	int	0x19

	; int 0x19 should never return.  In case it does anyway,
	; invoke the BIOS reset code...
	push 0xf000
	push 0xfff0
	retf
