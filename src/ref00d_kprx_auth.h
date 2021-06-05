/*
 * reF00D
 * Copyright (C) 2021, FAPS TEAM
 */

#ifndef _REF00D_KPRX_AUTH_H_
#define _REF00D_KPRX_AUTH_H_

#include <psp2kern/types.h>
#include "self.h"

typedef struct SceKprxAuthKey { // size is 0x180
	char key[0x20];
	char iv[0x10];
	uint64_t minver;
	uint64_t maxver;

	// offset 0x40
	uint32_t rsa_n[0x40];

	// offset:0x140
	int sce_type;
	int key_type;
	int self_type;
	int key_rev;

	int flags;
	char dbg_key_name[0x24];
	uint32_t magic;
	uint32_t hash;
} SceKprxAuthKey;

#define REF00D_KPRX_AUTH_KEY_NUMBER (0x17)

#define REF00D_KEY_FLAG_HAS_PROTOTYPE   (1 << 0)
#define REF00D_KEY_FLAG_HAS_SD_INTERNAL (1 << 1)

/*
 * Office functions
 */
int ref00d_auth_open(int *ctx);
int ref00d_auth_close(int ctx);

int ref00d_auth_header(int ctx, const void *header, SceSize header_size, SceSblSmCommContext130 *ctx130);

int ref00d_load_block(int ctx, void *buffer, SceSize len);

int ref00d_setup_segment(int ctx, int seg_idx);

/*
 * Custom functions
 */
int ref00d_kprx_auth_initialization(void);

int ref00d_get_internal_header(void *dst, SceSize *dstlen);

int ref00d_segment_num(int *num);

int ref00d_segment_info(int seg_idx, SceSelfAuthSegmentInfo *data);

int ref00d_kprx_auth_state(void);

int ref00d_kprx_gen_key_file(void);
int ref00d_kprx_set_key(void);
int ref00d_kprx_gen_keys(void);

#endif	/* _REF00D_KPRX_AUTH_H_ */
