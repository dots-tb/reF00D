/*
 * reF00D
 * Copyright (C) 2021, FAPS TEAM
 */

#include <psp2kern/types.h>
#include <stdint.h>
#include "ref00d_utils.h"

int __swap_data32(uint32_t *dst, const uint32_t *src, SceSize len){

	uint32_t val;
	int s1 = ((len & 4) != 0) ? 1 : 0;

	for(int i=0;i<(len >> 3);i++){
		val = __builtin_bswap32(src[(len >> 2) - i - 1]);
		dst[(len >> 2) - i - 1] = __builtin_bswap32(src[i]);
		dst[i] = val;
	}

	if(s1 != 0)
		dst[len >> 3] = __builtin_bswap32(dst[len >> 3]);

	return 0;
}

int __swap_data(void *dst, const void *src, SceSize len){

	if((len & 3) != 0)
		return -1;

	return __swap_data32(dst, src, len);
}
