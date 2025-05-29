PUBLIC enableVmx
PUBLIC readMsrWord
PUBLIC readReg
.code _text

enableVmx PROC PUBLIC
	PUSH RAX			    ; Save the state
	
	XOR RAX, RAX			; Clear the RAX
	MOV RAX, CR4

	OR RAX, 02000h	    	; Set the 14th bit
	MOV CR4, RAX
	
	POP RAX			     	; Restore the state
	RET
enableVmx ENDP

readMsrWord PROC PUBLIC
	RDMSR					; assumes the MSR needed is already in RCX.
	RET						; return EAX (lower 32 bits of MSR)
readMsrWord ENDP

readReg PROC PUBLIC
	CMP RCX, 0
	JE ReadCR0
	CMP RCX, 1
	JE ReadCR2
	CMP RCX, 3
	JE ReadCR3
	CMP RCX, 4
	JE ReadCR4

	MOV RAX, -1
	RET

	ReadCR0:
	MOV RAX, CR0
	RET

	ReadCR2:
	MOV RAX, CR2
	RET

	ReadCR3:
	MOV RAX, CR3
	RET

	ReadCR4:
	MOV RAX, CR4
	RET
readReg ENDP

END
