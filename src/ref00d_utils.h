/*
 * reF00D
 * Copyright (C) 2021, FAPS TEAM
 */

#ifndef _REF00D_UTILS_H_
#define _REF00D_UTILS_H_

#include <psp2kern/types.h>
#include <stdint.h>

int __swap_data(void *dst, const void *src, SceSize len);

int ref00dAesCbcDecrypt(const void *src, void *dst, int length, const void *key, SceSize keysize, void *iv);
int ref00dAes128Ctr(SceAesContext *ctx, void *dst, const void *src, SceSize length, void *iv);

#endif	/* _REF00D_UTILS_H_ */