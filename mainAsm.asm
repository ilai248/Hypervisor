PUBLIC AsmEnableVmxOperation
PUBLIC AsmVmxon
PUBLIC AsmVmptrld
PUBLIC AsmRdmsrWord
PUBLIC AsmReadRegister
.code _text

AsmEnableVmxOperation PROC PUBLIC
	PUSH RAX			    ; Save the state
	
	XOR RAX, RAX			; Clear the RAX
	MOV RAX, CR4

	OR RAX, 02000h	    	; Set the 14th bit
	MOV CR4, RAX
	
	POP RAX			     	; Restore the state
	RET
AsmEnableVmxOperation ENDP

AsmVmxon PROC PUBLIC
	VMXON QWORD PTR [RCX]	; The operand must be in memory.
	JC carry
	JZ zero
	MOV RAX, 0
	RET
	carry:
	MOV RAX, 1
	RET
	zero:
	MOV RAX, 2
	RET
AsmVmxon ENDP

AsmVmptrld PROC PUBLIC
	VMPTRLD QWORD PTR [RCX]	; The operand must be in memory.
	RET
AsmVmptrld ENDP

AsmRdmsrWord PROC PUBLIC
	RDMSR					; assumes the MSR needed is already in RCX.
	RET						; return EAX (lower 32 bits of MSR)
AsmRdmsrWord ENDP

AsmReadRegister PROC PUBLIC
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
AsmReadRegister ENDP

END
