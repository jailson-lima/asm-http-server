; HTTP Server

format PE64 console
entry start

section '.code' code executable
start:
    sub rsp, 40 ; Reserves stack space for 5 parameters: 8 * 5 = 40

    ; Get output handle
    mov rcx, -11
    call [GetStdHandle]
    mov [out_handle], rax

    ; Initialising socket structure

    mov rcx, 0x0202   ; MAKEWORD(2, 2) -> 0x0202
    mov rdx, wsa_data ; wsa_data -> memory address (8 bytes). Note that [wsa_data] -> memory block (408 bytes)
    call [WSAStartup] ; WSAStartup(MAKEWORD(2, 2), &wsa_data)

    ; Creating socket

    mov rcx, AF_INET
    mov rdx, SOCK_STREAM
    mov r8, IPPROTO_TCP
    call [socket]               ; rax = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    mov [main_socket], rax      ; main_socket = rax

    ; Prepare the sockaddr_in structure

    mov [sin_family], AF_INET ; server.sin_family = AF_INET

    xor rax, rax
    mov rcx, host
    call [inet_addr]  ; eax = inet_addr(host)
    mov [s_addr], eax ; server.sin_addr.s_addr = eax

    xor rax, rax
    xor rcx, rcx
    mov cx, [port]
    call [htons]       ; ax = htons(port)
    mov [sin_port], ax ; server.sin_port = ax

    ; Bind
    mov rcx, [main_socket]          ; [main_socket] -> memory block (8 bytes)
    mov rdx, server                 ; server -> memory address (8 bytes)
    mov r8, [size_socket_structure] ; size of server in bytes
    call [bind]

    ; Listen
    mov rcx, [main_socket] ; [main_socket] -> memory block (8 bytes)
    mov rdx, 0x7fffffff    ; maximum connections allowed by the operating system
    call [listen]

    ; Write message
    mov rcx, [out_handle]
    mov rdx, run_message
    mov r8, 27
    mov r9, characters_written
    mov qword [rsp + 8 * 4], 0
    call [WriteFile]

loop_accept:
    ; Accept
    mov rcx, [main_socket]        ; [main_socket] -> memory block (8 bytes)
    mov rdx, client               ; client -> memory address (8 bytes)
    mov r8, size_socket_structure ; Address for memory block (8 bytes) with the size of server in bytes
    call [accept]
    mov [new_socket], rax

    mov rbx, [new_socket]
    cmp rbx, -1
    je error_accept

    ; Receive
    mov rcx, [new_socket]
    mov rdx, request
    mov r8, 128 ; request length
    mov r9, 0
    call [recv]

    ; Calculates the length of the string up to the character: '\r' = 13
    mov rdi, request ; request = GET /route HTTP/1.1\r\n...
    mov rcx, -1
    mov rax, 13      ; character: '\r' = 13
    repne scasb
    neg rcx
    sub rcx, 2       ; request = GET /route HTTP/1.1\0\n...
    mov rax, rcx

    ; Put the character '\n' = 10 at the end of the requested route
    mov [request + rax - 9], 10 ; request = GET /route\nHTTP/1.1\0\n...
    sub rax, 8

    ; Write message
    mov rcx, [out_handle]
    mov rdx, request
    mov r8, rax
    mov r9, characters_written
    mov qword [rsp + 8 * 4], 0
    call [WriteFile]

    ; Send
    mov rcx, [new_socket]
    mov rdx, response
    mov r8, 110 ; response size
    mov r9, 0
    call [send]

    jmp loop_accept

error_accept:
    ; Write message
    mov rcx, [out_handle]
    mov rdx, error_message
    mov r8, 14
    mov r9, characters_written
    mov qword [rsp + 8 * 4], 0
    call [WriteFile]

    add rsp, 40
    ret

section '.data' data readable writeable
    ; Variables

    request rb 128
    response db 'HTTP/1.1 200 OK', 13, 10, 'Content-Type: text/plain; charset=utf-8', 13, 10, 'Connection: close', 13, 10, 'Content-Length: 11', 13, 10, 13, 10, 'HTTP Server', 0
    characters_written dd 0
    run_message db 'http server is running ...', 10, 0
    error_message db 'Accept failed', 10, 0

    out_handle dq 0             ; Output handle (HANDLE)
    wsa_data rb 408             ; WSADATA structure
    main_socket dq 0            ; main socket
    new_socket dq 0             ; new socket
    port dw 9000                ; port
    host db '127.0.0.1', 0      ; hostname
    size_socket_structure dq 16 ; Size of socket structure

    server:                                 ; socket structure (sockaddr_in)
        sin_family dw 0                     ; int16
        sin_port dw 0                       ; uint16
        sin_addr:
            s_addr dd 0                     ; uint32 
        sin_zero db 0, 0, 0, 0, 0, 0, 0, 0  ; char[8]

    client:                                 ; socket structure (sockaddr_in)
        csin_family dw 0                    ; int16
        csin_port dw 0                      ; uint16
        csin_addr:
            cs_addr dd 0                    ; uint32 
        csin_zero db 0, 0, 0, 0, 0, 0, 0, 0 ; char[8]

    ; Constants

    AF_INET = 2         ; Address family specification
    SOCK_STREAM = 1     ; Type specification for the new socket
    IPPROTO_TCP = 6     ; Protocol to be used
    INVALID_SOCKET = -1 ; Invalid socket constant

section '.idata' import data readable
    dd 0, 0, 0, rva kernel_name, rva kernel_table
    dd 0, 0, 0, rva socket_name, rva socket_table
    dd 0, 0, 0, 0, 0

    kernel_table:
    	GetStdHandle dq rva _GetStdHandle
        WriteFile dq rva _WriteFile
        dq 0

    socket_table:
        WSAStartup dq rva _WSAStartup
        socket dq rva _socket
        inet_addr dq rva _inet_addr
        htons dq rva _htons
        bind dq rva _bind
        listen dq rva _listen
        accept dq rva _accept
        recv dq rva _recv
        send dq rva _send
        dq 0

    kernel_name db 'kernel32.dll', 0
    socket_name db 'Ws2_32.dll', 0

    _GetStdHandle db 0, 0, 'GetStdHandle', 0
    _WriteFile db 0, 0, 'WriteFile', 0

    _WSAStartup db 0, 0, 'WSAStartup', 0
    _socket db 0, 0, 'socket', 0
    _inet_addr db 0, 0, 'inet_addr', 0
    _htons db 0, 0, 'htons', 0
    _bind db 0, 0, 'bind', 0
    _listen db 0, 0, 'listen', 0
    _accept db 0, 0, 'accept', 0
    _recv db 0, 0, 'recv', 0
    _send db 0, 0, 'send', 0
