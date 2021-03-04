
	.align 4
	.text
	.cpu cortex-a9
	.arch armv7-a
	.syntax unified
	.thumb
	.thumb_func
	.fpu neon

	.global ref00d_aes_cbc_decrypt
	.type   ref00d_aes_cbc_decrypt, %function

@ void ref00d_aes_cbc_decrypt(SceAesContext *ctx, const void *src, void *dst, int length, void *iv);

ref00d_aes_cbc_decrypt:
	push {r4, r5, r6, r7, r8, r9, r10, lr}
	vpush {d8, d9, d10, d11, d12, d13}

	// load iv addr
	ldr r4, [sp, #0x50]
	pld [r4, #0xc0]
	vldm r4, {d12, d13} // iv

	mov r5, r0
	mov r6, r1
	mov r7, r2
	mov r8, r3

start:
	// storeNextIv = src
	pld [r6, #0xc0]
	vldmia r6!, {d10, d11}

	mov r0, r5
	sub r1, r6, #0x10
	mov r2, r7
	blx ksceAesDecrypt1 // (SceAesContext *ctx, const void *src, void *dst);

	// dst ^= iv
	pld [r7, #0xc0]
	vldm r7, {d8, d9} // load dst

	veor d8, d12
	veor d9, d13
	vstmia r7!, {d8, d9}

	// iv = storeNextIv
	vmov d12, d10
	vmov d13, d11

	subs r8, 0x10
	bne start

	vstmia r4!, {d12, d13}

	vpop {d8, d9, d10, d11, d12, d13}
	pop {r4, r5, r6, r7, r8, r9, r10, pc}

	.data
