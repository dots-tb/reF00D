/*
 * reF00D
 * Copyright (C) 2021, FAPS TEAM
 */

#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/utils.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/ssmgr.h>
#include <psp2kern/sblaimgr.h>
#include <psp2kern/types.h>
#include "self.h"
#include "elf.h"
#include "ref00d_types.h"
#include "ref00d_utils.h"
#include "ref00d_kprx_auth.h"
#include "ref00d_rsa_engine.h"

#define REF00D_HEADER_RANGE_CHECK(offset, size) (size >= header_size || (offset + size) > header_size)

int kscePmMgrGetProductMode(uint8_t *res);

typedef struct SceNpDrmRsaKey {
	const void *n;
	const void *k; // e/d
} SceNpDrmRsaKey;

/* ================================ data section ================================ */

char *ref00d_private_header;
char ref00d_private_iv[0x10];

SceUID semaid;

int is_auth_success, currentKey;

SceAesContext ref00d_kprx_aes_ctx;

SceSelfAuthHeaderInfo  *pHeaderInfo;
SceSelfAuthSegmentInfo *pSegmentInfo;

void *pKeyBase;

SceKprxAuthKey *pKprxKey;

const SceKprxAuthKey ref00d_kprx_user_rev0 = {
	.key       = {
		0x26, 0xFC, 0x30, 0x3E, 0x52, 0x37, 0x07, 0x8E, 0x51, 0x49, 0x36, 0xB3, 0x65, 0xC1, 0x6B, 0xB5,
		0xD6, 0xEC, 0xBD, 0xF4, 0xBC, 0x19, 0x3C, 0x1F, 0xCC, 0x94, 0x19, 0xE9, 0x8F, 0x9C, 0x58, 0xEC
	},
	.iv        = {
		0x91, 0x1E, 0xB4, 0x1B, 0x7C, 0x05, 0x0D, 0xD5, 0x28, 0xD9, 0xC9, 0x57, 0x04, 0x6A, 0xB7, 0x50
	},
	.minver    = 0x00000000000,
	.maxver    = 0xFFFFFFFFFFF,
	.rsa_n     = {
		0x2E7EF51F, 0xA6190227, 0x82F60908, 0xC3DB0726,
		0x06F19850, 0xE2921C69, 0xBEB02510, 0x1C057F60,
		0x61865E9E, 0xDC423C5E, 0xD6811C7F, 0x9B45EB03,
		0x699A6C7F, 0xA42A154F, 0xE2B21D5F, 0x59E04FB5,
		0xEE8A696C, 0x4456A38E, 0xF2A1C7D3, 0x18CB31AF,
		0x7674351B, 0x8AD85E3D, 0x768274C9, 0x1B49944B,
		0x5EAD3E63, 0xE08E4B4C, 0x48ABDD93, 0x9E32E55F,
		0x8E69C2B6, 0x81FBC483, 0x8F9D8786, 0x19882B18,
		0x59883A03, 0x0B9CFFD7, 0x7D8B5C7E, 0x4F189304,
		0x6D6E7316, 0xA134E510, 0xEC55326B, 0xB4056A6A,
		0x5BAC6E64, 0xE904F313, 0x4EBED786, 0x8AFB8700,
		0xE6845FCA, 0xEEB08492, 0x516FB745, 0x625BAB36,
		0xA8D45DFB, 0x1630A238, 0x51EB355B, 0x4C527F5E,
		0xB1108A1A, 0x59DC4A4D, 0x4FE7AEC0, 0x29D23C3F,
		0xC1702467, 0xDC2972D9, 0x0B713EFC, 0x9DBDAF92,
		0x88D1C2F1, 0xF8E03B39, 0xFD671E48, 0xA84D9DF6
	},
	.sce_type  = SELF,
	.key_type  = METADATA,
	.self_type = REF00D_USER,
	.key_rev   = 0,
	.flags     = 0,
	.dbg_key_name = "FapsReF00DKeyset0User",
};

const SceKprxAuthKey ref00d_kprx_kernel_rev0 = {
	.key       = {
		0xC4, 0x8A, 0x3B, 0x69, 0x85, 0x61, 0x9D, 0xDA, 0xDE, 0x50, 0x4B, 0xD9, 0x00, 0xF9, 0x2A, 0xE5,
		0x30, 0x5C, 0xAC, 0x79, 0xF7, 0xD1, 0xF9, 0xE3, 0xE8, 0x79, 0xFC, 0x2E, 0x36, 0xBA, 0x16, 0x89
	},
	.iv        = {
		0x8C, 0xC6, 0x82, 0xC9, 0x0B, 0x5A, 0xAA, 0x45, 0x3E, 0xC7, 0x87, 0xAE, 0x9D, 0xA4, 0x7B, 0xDB
	},
	.minver    = 0x00000000000,
	.maxver    = 0xFFFFFFFFFFF,
	.rsa_n     = {
		0x6BE59F31, 0x0A8BEBC9, 0x0CAF5F0F, 0x359A603B,
		0xD1DDF9F2, 0xDE76BF52, 0x8E6B4F33, 0x06537D12,
		0x63BE26C2, 0xBE22B6D7, 0x897877B7, 0x60E33A28,
		0xC62A23C1, 0x63F5F262, 0x7140FBD9, 0xF81A6DAA,
		0xC482434E, 0x09BD9CDF, 0x17CAEF58, 0x2B6145C8,
		0x7F217474, 0xB86F8408, 0x296882E0, 0xD72A24AB,
		0x23068050, 0x0A328A66, 0x89173F18, 0xF9B05072,
		0xC37CD87C, 0x1668B9BB, 0xDBD0583E, 0x43D49A60,
		0x1FB3831A, 0xB44D9180, 0xFFD820B7, 0xFFF48D5B,
		0x17BDC29A, 0x4FB02D8E, 0x2BA106FB, 0x8D0E51D9,
		0xBEF576DB, 0x034C98EC, 0xBE92B829, 0x501519A8,
		0xD0BA0DD0, 0x50E407E7, 0x3E6DA717, 0x48759C58,
		0x5DB63A8D, 0x98DA85B7, 0x5B4EFC89, 0x99A83C17,
		0x01ECACA3, 0x454624BE, 0xCEAE36EB, 0x72505A1D,
		0xF122CF04, 0x8F61A350, 0x4D1234B9, 0x03DE39E3,
		0x6D11F36A, 0x44C5D95F, 0x3C960FCA, 0xA4EAD3C1
	},
	.sce_type  = SELF,
	.key_type  = METADATA,
	.self_type = REF00D_KERNEL,
	.key_rev   = 0,
	.flags     = 0,
	.dbg_key_name = "FapsReF00DKeyset0Kernel",
};

/* ================================ data section ================================ */

int ref00d_kprx_add_key(const SceKprxAuthKey *key){

	SceKprxAuthKey *loc_key;

	loc_key = ksceKernelAllocHeapMemory(0x1000B, sizeof(*loc_key));
	if(loc_key == NULL)
		return -1;

	memcpy(loc_key, key, sizeof(*loc_key));

	loc_key->next = pKprxKey;
	pKprxKey = loc_key;

	return 0;
}

int kprxAuthKeysSetup(void){

	ref00d_kprx_add_key(&ref00d_kprx_user_rev0);
	ref00d_kprx_add_key(&ref00d_kprx_kernel_rev0);

	return 0;
}

int ref00d_kprx_auth_initialization(void){

	int res;

	pKprxKey = NULL;

	res = kprxAuthKeysSetup();
	if(res < 0){
		printf("%s:kprxAuthKeysSetup failed 0x%X\n", __FUNCTION__, res);
		return res;
	}

	void *memptr = ksceKernelAllocHeapMemory(0x1000B, 0x103F);
	if(memptr == NULL){
		printf("%s:sceKernelAllocHeapMemory failed\n", __FUNCTION__);
		return -1;
	}

	ref00d_private_header = (char *)(((uintptr_t)memptr + 0x3F) & ~0x3F);

	return 0;
}

static const SceKprxAuthKey *ref00d_kprx_auth_get_key(int key_type, int sce_type, uint64_t sys_ver, int key_rev, int selftype, int flags){

	SceKprxAuthKey *kprx_key = pKprxKey;

	while(kprx_key != NULL){
		if(
			(kprx_key->flags     == flags) &&
			(kprx_key->self_type == selftype) && (kprx_key->key_rev  == key_rev) &&
			(kprx_key->key_type  == key_type) && (kprx_key->sce_type == sce_type) &&
			(sys_ver >= kprx_key->minver) && (sys_ver <= kprx_key->maxver)
		){
			printf("Key: %s\n", kprx_key->dbg_key_name);
			return kprx_key;
		}
		kprx_key = kprx_key->next;
	}

	return NULL;
}

int remove_npdrm_personalize(cf_header *cf_hdr, const void *key, const void *klicensee){

	char klicensee_dec[0x10];
	char iv[0x20];

	void *decrypt_point = &ref00d_private_header[sizeof(cf_header) + cf_hdr->m_ext_header_size];

	memset(&iv, 0, sizeof(iv));

	// klicensee to metadata decrypt key
	ref00dAesCbcDecrypt(klicensee, &klicensee_dec, 0x10, key, 0x80, &iv);

	// decrypt metadata
	ref00dAesCbcDecrypt(decrypt_point, decrypt_point, sizeof(SceSelfAuthHeaderKey), klicensee_dec, 0x80, &iv[0x10]);

	return 0;
}

int setup_ac(const void *data, int bit){

	if(bit > 0xFF)
		return -1;

	((char *)data)[(bit & ~7) >> 3] |= (1 << (~bit & 7));

	return 0;
}

int check_ac(const void *data, int bit){
	return ((((char *)data)[(bit & ~7) >> 3] & (1 << (~bit & 7))) != 0) ? 1 : 0;
}

int decrypt_certified_personalize(const SceKprxAuthKey *key_info){

	SceSelfAuthHeaderKey *pHeaderKey;

	cf_header *cf_hdr = (cf_header *)ref00d_private_header;
	void *decrypt_point;
	char rw_iv[0x10];
	char ref00d_private_header_iv[0x10];

	memcpy(rw_iv, key_info->iv, sizeof(rw_iv));

	decrypt_point = &ref00d_private_header[sizeof(cf_header) + cf_hdr->m_ext_header_size];

	ref00dAesCbcDecrypt(decrypt_point, decrypt_point, sizeof(SceSelfAuthHeaderKey), key_info->key, 0x100, rw_iv);

	pHeaderKey = decrypt_point;
	decrypt_point += sizeof(SceSelfAuthHeaderKey);

	memcpy(ref00d_private_header_iv, pHeaderKey->iv, 0x10);

	SceSize DecryptSize = cf_hdr->m_header_length - (sizeof(cf_header) + cf_hdr->m_ext_header_size + sizeof(SceSelfAuthHeaderKey));

	ref00dAesCbcDecrypt(decrypt_point, decrypt_point, DecryptSize, pHeaderKey->key, 0x80, ref00d_private_header_iv);

	pHeaderInfo = decrypt_point;
	decrypt_point += sizeof(SceSelfAuthHeaderInfo);

	/*
	 * Does PS Vita only support RSA2048(type5)
	 */
	if(pHeaderInfo->sig_type != 5){
		printf("unknown sig type : 0x%X\n", pHeaderInfo->sig_type);
		return 0x800F0625;
	}

	SceSize header_size = ((cf_header *)ref00d_private_header)->m_header_length;

	if(REF00D_HEADER_RANGE_CHECK(pHeaderInfo->offset_sig, 0x100))
		return 0x800F0624;

	void *pSelfRsaSig = (void *)(ref00d_private_header + pHeaderInfo->offset_sig);

	__swap_data(pSelfRsaSig, pSelfRsaSig, 0x100); // Big endian to little endian

	uint32_t kprx_auth_rsa_buffer_e[0x40];
	memset(kprx_auth_rsa_buffer_e, 0, sizeof(kprx_auth_rsa_buffer_e));
	kprx_auth_rsa_buffer_e[0] = 0x10001;

	int res;

	ref00dRsaEngineRequest(pSelfRsaSig, pSelfRsaSig, kprx_auth_rsa_buffer_e, key_info->rsa_n);

	char header_hash[0x20];
	memset(header_hash, 0, sizeof(header_hash));

	ksceSha256Digest(ref00d_private_header, (SceSize)pHeaderInfo->offset_sig, header_hash);

	res = ref00dRsaEngineWaitWork();
	if(res < 0){
		printf("sceNpDrmRsaModPower failed\n");
		return 0x800F0516;
	}

	__swap_data(pSelfRsaSig, pSelfRsaSig, 0x20);

	if(memcmp(header_hash, pSelfRsaSig, 0x20) != 0){
		printf("Header hash not match on RSA sig and raw header\n");
		return 0x800F0516;
	}

	pSegmentInfo = decrypt_point;
	decrypt_point += (sizeof(SceSelfAuthSegmentInfo) * pHeaderInfo->section_num);

	pKeyBase = decrypt_point;

	return 0;
}

int decrypt_module(const void *header, SceSize header_size, SceSblSmCommContext130 *ctx130){

	int res;
	const SceKprxAuthKey *curr_key;
	uint64_t sysver = 0LL;
	SceSelfAuthInfo self_auth_info;
	cf_header *cf_hdr;
	ext_header *ext_hdr;
	SCE_appinfo *appinfo;
	PSVita_CONTROL_INFO *control_info;

	if((header_size > 0x1000) || (((SCE_header *)header)->header_len > 0x1000))
		return -1;

	memcpy(ref00d_private_header, header, header_size);
	memcpy(&self_auth_info, &ctx130->self_auth_info, sizeof(SceSelfAuthInfo));

	cf_hdr       = (cf_header           *)(ref00d_private_header);

	if((cf_hdr->m_magic != 0x454353) || (cf_hdr->m_version != 3) || ((cf_hdr->attributes.m_platform & 0x40) == 0) || ((cf_hdr->m_ext_header_size & 0xF) != 0))
		return 0x800F0624;

	if(REF00D_HEADER_RANGE_CHECK(sizeof(cf_header), cf_hdr->m_ext_header_size))
		return 0x800F0624;

	ext_hdr      = (ext_header          *)(&ref00d_private_header[sizeof(cf_header)]);

	if(REF00D_HEADER_RANGE_CHECK(ext_hdr->appinfo_offset, sizeof(SCE_appinfo)))
		return 0x800F0624;

	if(REF00D_HEADER_RANGE_CHECK(ext_hdr->controlinfo_offset, sizeof(PSVita_CONTROL_INFO)))
		return 0x800F0624;

	appinfo      = (SCE_appinfo         *)(&ref00d_private_header[ext_hdr->appinfo_offset]);
	control_info = (PSVita_CONTROL_INFO *)(&ref00d_private_header[ext_hdr->controlinfo_offset]);

	SceUInt32 offset_tmp = ext_hdr->controlinfo_offset;

	int next = 0;

	do {
		next = control_info->next & 1;
		switch(control_info->type){
		case 4:
			sysver = control_info->PSVita_elf_digest_info.min_required_fw;
			break;
		case 7:
			memcpy(&self_auth_info.secret.shared_secret_0, control_info->PSVita_shared_secret_info.shared_secret_0, 0x10);
			break;
		}

		if(REF00D_HEADER_RANGE_CHECK(offset_tmp, control_info->size))
			return 0x800F0624;

		offset_tmp += control_info->size;

		control_info = (PSVita_CONTROL_INFO *)(((uintptr_t)control_info) + control_info->size);
	} while(next == 1);

	if(sysver == 0LL)
		sysver = appinfo->version;

	if(appinfo->self_type == APP){
		curr_key = ref00d_kprx_auth_get_key(NPDRM, cf_hdr->m_category, sysver, (cf_hdr->attributes.m_sdk_type >= 2) ? 1 : 0, appinfo->self_type, 0);
		if(curr_key == NULL)
			return -1;

		res = remove_npdrm_personalize(cf_hdr, curr_key->key, &self_auth_info.secret.klicensee);
		if(res < 0)
			return res;
	}

	curr_key = ref00d_kprx_auth_get_key(METADATA, cf_hdr->m_category, sysver, cf_hdr->attributes.m_sdk_type, appinfo->self_type, 0);
	if(curr_key == NULL){
		printf(
			"Not found to key. category:0x%08X sysver:0x%llX sdk_type:0x%X self_type:0x%X\n",
			cf_hdr->m_category, sysver, cf_hdr->attributes.m_sdk_type, appinfo->self_type
		);
		return -1;
	}

	/*
	 * decrypt and get section
	 */
	res = decrypt_certified_personalize(curr_key);
	if(res < 0){
		printf("decrypt_certified_personalize failed.\n");
		return res;
	}

	const SceSelfAuthMetaInfo *pMetaInfo = (const SceSelfAuthMetaInfo *)(((uintptr_t)pKeyBase) + (pHeaderInfo->seg_keys_area_size * 0x10));

	offset_tmp = (SceUInt32)(((uintptr_t)pKeyBase) - ((uintptr_t)ref00d_private_header));

	do {
		next = pMetaInfo->next & 1;
		switch(pMetaInfo->type){
		case 1:
			memcpy(&self_auth_info.capability, &pMetaInfo->PSVITA_caps_info.capability, sizeof(self_auth_info.capability));
			break;
		case 3:
			memcpy(&self_auth_info.attribute, &pMetaInfo->PSVITA_attr_info.attributes, sizeof(self_auth_info.attribute));
			break;
		}

		if(REF00D_HEADER_RANGE_CHECK(offset_tmp, pMetaInfo->size))
			return 0x800F0624;

		offset_tmp += pMetaInfo->size;

		pMetaInfo = (SceSelfAuthMetaInfo *)(((uintptr_t)pMetaInfo) + pMetaInfo->size);
	} while(next == 1);

	if(appinfo->self_type >= 0x10000){

		int ac_val = check_ac(&self_auth_info.attribute, 29);

		if(ksceSblAimgrIsDEX() != 0 && ac_val == 0){
			printf("[%-15s] %s : %s = %d\n", "Error", "System product", "DEX", ksceSblAimgrIsDEX());
			return 0x800F0516;
		}

		ac_val = check_ac(&self_auth_info.attribute, 30);

		if(ksceSblAimgrIsTest() != 0 && ac_val == 0){
			printf("[%-15s] %s : %s = %d\n", "Error", "System product", "Test", ksceSblAimgrIsTest());
			return 0x800F0516;
		}

		if(ksceSblAimgrIsTool() != 0 && ac_val == 0){
			printf("[%-15s] %s : %s = %d\n", "Error", "System product", "Tool", ksceSblAimgrIsTool());
			return 0x800F0516;
		}

		ac_val = check_ac(&self_auth_info.attribute, 31);

		if(ksceSblAimgrIsCEX() != 0 && ac_val == 0){
			printf("[%-15s] %s : %s = %d\n", "Error", "System product", "CEX", ksceSblAimgrIsCEX());
			return 0x800F0516;
		}

		uint8_t is_production_mode = 0;

		kscePmMgrGetProductMode(&is_production_mode);

		ac_val = check_ac(&self_auth_info.attribute, 32); // Requires production mode
		if(ac_val != 0 && is_production_mode == 0){
			printf("[%-15s] %s : %s = %d\n", "Error", "Manufacturing mode", "Required", 1);
			return 0x800F0516;
		}

		ac_val = check_ac(&self_auth_info.attribute, 33); // Prohibit production mode
		if(ac_val != 0 && is_production_mode != 0){
			printf("[%-15s] %s : %s = %d\n", "Error", "Manufacturing mode", "Required", 0);
			return 0x800F0516;
		}
	}

	self_auth_info.program_authority_id = appinfo->authid;

	memcpy(&ctx130->self_auth_info, &self_auth_info, sizeof(SceSelfAuthInfo));

	return 0;
}

int ref00d_wait_sema(void){

	int res;

	res = ksceKernelWaitSema(semaid, 1, NULL);
	if(res > 0)
		res = 0;

	return res;
}

int ref00d_auth_open(int *ctx){

	int res;

	is_auth_success = 0;

	if(ctx == NULL){
		printf("ref00d_auth_open ctx == NULL\n");
		return -1;
	}

	res = ref00d_wait_sema();
	if(res == 0){
		*ctx = 1;
	}

	return res;
}

int ref00d_auth_close(int ctx){

	int res;

	is_auth_success = 0;

	if(ctx != 1){
		printf("ref00d_auth_close ctx != 1\n");
		return -1;
	}

	res = ksceKernelSignalSema(semaid, 1);
	if(res > 0)
		res = 0;

	return res;
}

int ref00d_auth_header(int ctx, const void *header, SceSize header_size, SceSblSmCommContext130 *ctx130){

	int res;

	if(ctx != 1){
		printf("ref00d_auth_header : 0x800F0624\n");
		return 0x800F0624;
	}

#if defined(REF00D_DEBUG) && (REF00D_DEBUG == 1)
	SceInt64 time_s, time_e;
	time_s = ksceKernelGetSystemTimeWide();
#endif

	res = decrypt_module(header, header_size, ctx130);

	is_auth_success = ((res >> 0x1F) ^ 1) & 1;

#if defined(REF00D_DEBUG) && (REF00D_DEBUG == 1)
	time_e = ksceKernelGetSystemTimeWide();
	printf("\tdecrypt_module : 0x%X, is_auth_success %X, time:%6lld usec\n", res, is_auth_success, time_e - time_s);
#endif

	return res;
}

int ref00d_load_block(int ctx, void *buffer, SceSize len){

	if((ctx != 1) || (is_auth_success == 0)){
		printf("\tref00d_load_block : 0x800F0624\n");
		return 0x800F0624;
	}

#if defined(REF00D_DEBUG) && (REF00D_DEBUG == 1)
	SceInt64 time_s, time_e;
	time_s = ksceKernelGetSystemTimeWide();
#endif

	if(pSegmentInfo[currentKey].section_encryption == AES128CTR){
		const void *key = (const void *)(((uintptr_t)pKeyBase) + (pSegmentInfo[currentKey].section_key_idx * 0x10));

		if(len < 0x300){ // Some initialization of DMAC5 takes 80 usec, so it is faster to run normal AES.
			__swap_data(ref00d_private_iv, ref00d_private_iv, 0x10);
			ref00dAes128Ctr(&ref00d_kprx_aes_ctx, buffer, buffer, len, ref00d_private_iv);
			__swap_data(ref00d_private_iv, ref00d_private_iv, 0x10);
		}else{
			ksceSblDmac5AesCtrDec(buffer, buffer, len, key, 0x80, ref00d_private_iv, 1);
		}

#if defined(REF00D_DEBUG) && (REF00D_DEBUG == 1)
		time_e = ksceKernelGetSystemTimeWide();
		printf("\tref00d_load_block %p, 0x%08X time:%6lld usec\n", buffer, len, time_e - time_s);
#endif
	}else{
		printf("\tref00d_load_block not supported format\n");
	}

	return 0;
}

int ref00d_setup_segment(int ctx, int seg_idx){

	if((ctx != 1) || (is_auth_success == 0)){
		printf("ref00d_setup_segment : 0x800F0624\n");
		return 0x800F0624;
	}

	for(int i=0;i<pHeaderInfo->section_num;i++){
		if(pSegmentInfo[i].section_idx == seg_idx){

			printf("\tref00d_setup_segment : found key idx : 0x%X\n", i);

			currentKey = i;

			const void *key = (const void *)(((uintptr_t)pKeyBase) + (pSegmentInfo[currentKey].section_key_idx * 0x10));
			ksceAesInit1(&ref00d_kprx_aes_ctx, 0x80, 0x80, key);

			const void *iv  = (const void *)(((uintptr_t)pKeyBase) + (pSegmentInfo[currentKey].section_iv_idx  * 0x10));
			__swap_data(ref00d_private_iv, iv, sizeof(ref00d_private_iv)); // For Dmac AesCtr

			return pSegmentInfo[i].section_compression;
		}
	}

	printf("not found key idx\n");
	return -1;
}

int ref00d_get_internal_header(void *dst, SceSize *dstlen){

	if(is_auth_success != 1)
		return -1;

	if(((SCE_header *)ref00d_private_header)->header_len < *dstlen)
		*dstlen = ((SCE_header *)ref00d_private_header)->header_len;

	memcpy(dst, ref00d_private_header, *dstlen);

	return 0;
}

int ref00d_segment_num(int *num){

	if(is_auth_success == 0)
		return 0x800F0624;

	*num = pHeaderInfo->section_num;
	return 0;
}

int ref00d_segment_info(int seg_idx, SceSelfAuthSegmentInfo *data){

	if(is_auth_success == 0)
		return 0x800F0624;

	for(int i=0;i<pHeaderInfo->section_num;i++){
		if(pSegmentInfo[i].section_idx == seg_idx){
			memcpy(data, &pSegmentInfo[i], sizeof(SceSelfAuthSegmentInfo));
			return 0;
		}
	}

	return -1;
}

int ref00d_kprx_auth_state(void){

	if(is_auth_success == 0)
		return 0x800F0624;

	return 0;
}
