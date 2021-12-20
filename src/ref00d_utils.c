/*
 * reF00D
 * Copyright (C) 2021, FAPS TEAM
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/utils.h>
#include <psp2kern/kernel/sysclib.h>
#include <stdint.h>
#include "ref00d_utils.h"

void ref00d_aes_cbc_decrypt(SceAesContext *ctx, const void *src, void *dst, int length, void *iv);

int __swap_data32(uint32_t *dst, const uint32_t *src, SceSize len){

	uint32_t val;
	int s1 = ((len & 4) != 0) ? 1 : 0;

	for(int i=0;i<(len >> 3);i++){
		val = __builtin_bswap32(src[(len >> 2) - i - 1]);
		dst[(len >> 2) - i - 1] = __builtin_bswap32(src[i]);
		dst[i] = val;
	}

	if(s1 != 0)
		dst[len >> 3] = __builtin_bswap32(src[len >> 3]);

	return 0;
}

int __swap_data(void *dst, const void *src, SceSize len){

	if((len & 3) != 0)
		return -1;

	return __swap_data32(dst, src, len);
}

int ref00dAesCbcDecrypt(const void *src, void *dst, int length, const void *key, SceSize keysize, void *iv){

	SceAesContext ctx;
	memset(&ctx, 0, sizeof(ctx));

	if((length & 0xF) != 0)
		return -1;

	ksceAesInit1(&ctx, 128, keysize, key);
	ref00d_aes_cbc_decrypt(&ctx, src, dst, length, iv);

	return 0;
}

int ref00dAes128Ctr(SceAesContext *ctx, void *dst, const void *src, SceSize length, void *iv){

	char iv_enc[0x10];

	int n = (length & ~(0x10 - 1)) >> 4;
	int x = length & (0x10 - 1);

	for(int i=0;i<n;i++){
		ksceAesEncrypt1(ctx, iv, iv_enc);
		for(int p=0;p<0x10;p++){
			((char *)dst)[p] = ((char *)src)[p] ^ iv_enc[p];
		}

		dst += 0x10; src += 0x10;

		int c = 1;
		for(int p=0;p<0x10;p++){
			((char *)iv)[0xF - p] += c; c = (((char *)iv)[0xF - p] - c) == -1;
		}
	}

	if(x != 0){
		ksceAesEncrypt1(ctx, iv, iv_enc);
		for(int p=0;p<x;p++){
			((char *)dst)[p] = ((char *)src)[p] ^ iv_enc[p];
		}
	}

	return 0;
}
