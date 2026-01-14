format PE GUI 4.0
entry start

include 'win32ax.inc'

section '.text' code readable executable

start:
        push 0
        push title
        push message
        push 0
        call [MessageBoxA]

        push 0
        call [ExitProcess]

section '.data' data readable writeable

message db 'Hello world!',0
title   db 'PE test',0

abs_ptr dd message

section '.idata' import data readable writeable

library kernel32,'KERNEL32.DLL',\
        user32,'USER32.DLL'

import kernel32,\
       ExitProcess,'ExitProcess'

import user32,\
       MessageBoxA,'MessageBoxA'

section '.reloc' fixups data readable discardable  ; <-- добавили .reloc
