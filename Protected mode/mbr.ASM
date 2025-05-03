org 7c00h
use16

call clear_screen
lea ax, [stage_1_str]
push ax
call print
call new_line

call load_mbr

load_mbr:
        cli
        MOV SP, 0x7c00
        XOR AX, AX
        MOV SS, AX
        MOV ES, AX
        MOV DS, AX
        PUSH DX
        mov si, 0x7c00
        mov di, 0x0600
        mov cx, 0x200
        cld
        rep movsb

        jmp near protected_mode - $$ + 0x0600 ; calc right offset to jump

protected_mode:
        lea ax, [stage_2_str]
        push ax
        call print
        call new_line
        ; ---------------------
        ; Load GDT
        ; ---------------------
        cli
        lgdt [gdt_descriptor]

        ; ---------------------
        ; Print notify message
        ; ---------------------
        lea ax, [gdt_loaded_str]
        push ax
        call print
        call new_line

        mov eax, cr0
        or eax, 1         ; Set PE
        mov cr0, eax

        xchg bx, bx

        ; JMP to 32-bit code
        jmp 0x08:protected_entry


print:
        push bp
        mov bp, sp
        xor cx, cx
        mov si, [bp+4]
        loop_print:
                lodsb
                test al, al
                jz end_print
                mov ah, 0Eh
                int 10h
                loop loop_print
    
        end_print:
                mov sp, bp
                pop bp
                ret

new_line:
        mov ah, 0Eh
        mov al, 0Dh
        int 10h
        mov al, 0Ah
        int 10h
        ret

clear_screen:
        mov ah, 06h
        mov al, 0
        mov bh, 0x07
        mov cx, 0x0000
        mov dx, 0x184F
        int 10h

        mov ah, 02
        mov bh, 0
        mov dh, 0
        mov dl, 0
        int 10h
        ret

; ----------------------
; protected mode
; ----------------------
use32
protected_entry:
        xchg bx, bx

        mov ax, 0x20
        mov es, ax
        mov edi, 0
        mov ax, 0x1F20
        mov ecx, 80*25
        rep stosw


        mov ax, 0x20         ; gdt_vga
        mov es, ax

        mov edi, 0
        mov word [es:edi], 0x0750   ; 'P'
        mov word [es:edi+2], 0x0745 ; 'E'
        jmp $

; ----------------------------
; GDT table
; ----------------------------
gdt_start:
    dq 0                      ; NULL descriptor

gdt_code:                     ; CODE Sergment: base=0, limit=4GB
    dw 0xFFFF                 ; Limit low
    dw 0x0000                 ; Base low
    db 0x00                   ; Base mid
    db 10011010b              ; Access: present, ring 0, executable, readable
    db 11001111b              ; Flags: granularity=4KB, 32-bit, limit high
    db 0x00                   ; Base high

gdt_data:                     ; Data segment: base=0, limit=4GB
    dw 0xFFFF
    dw 0x0000
    db 0x01
    db 10010010b              ; Access: present, ring 0, data, writable
    db 11001111b
    db 0x00

gdt_stack:                   ; Stack segment
    dw 0xFFFF                ; Limit low
    dw 0x0000                ; Base low
    db 0x09                  ; Base mid = 0x09 > base = 0x00090000
    db 10010110b             ; Access: present, ring 0, data, writable, expand-down
    db 01000000b             ; Flags: G=0, D=1 (bytes granularity), limit high = 0
    db 0x00                  ; Base high

gdt_vga:
    dw 3999              ; Limit: 4000 (80x25x2 - 1)
    dw 0x8000            ; base low = 0xB8000 & 0xFFFF
    db 0x0B              ; base mid = 0xB8000 >> 16 = 0x0B
    db 10010010b         ; RW
    db 01000000b
    db 0x00

gdt_end:

; ----------------------------
; GDTR (GDT Descriptor)
; ----------------------------
gdt_descriptor:
    dw gdt_end - gdt_start - 1    ; ?????? GDT - 1
    dd gdt_start                  ; ????? GDT



stage_1_str db 'MBR exectuion stage 1 -> moving MBR from 0x7c00 to 0x0600', 0
stage_2_str db 'MBR exectuion stage 2 -> executing from new location', 0
gdt_loaded_str db 'GDT loaded. Ready for CR0 update.', 0
db 510-($-$$) dup(0), 0x55, 0xaa
buf: