/*
 * reF00D
 * Copyright (C) 2021, FAPS TEAM
 */

#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/utils.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/ssmgr.h>
#include <psp2kern/sblaimgr.h>
#include "self.h"
#include "elf.h"
#include "ref00d_types.h"
#include "ref00d_utils.h"
#include "ref00d_kprx_auth.h"

int module_get_offset(SceUID pid, SceUID modid, int segidx, uint32_t offset, uintptr_t *dst);

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

SceSelfAuthHeaderInfo  *pHeaderInfo;
SceSelfAuthSegmentInfo *pSegmentInfo;

void *pKeyBase;

int (* sceNpDrmRsaModPower)(void *dst, const void *src, SceNpDrmRsaKey *pParam, int size);

/* ================================ data section ================================ */

extern const SceKprxAuthKey kprx_auth_key_list[];

const unsigned char key_seed[] = {
	0x4D, 0xE9, 0xF0, 0x27, 0x67, 0x73, 0x44, 0x5B, 0x76, 0x9D, 0xE8, 0xC8, 0x5A, 0x90, 0x61, 0xA2,
	0x19, 0x29, 0x6F, 0xC2, 0x8B, 0xEB, 0x2D, 0x87, 0x9A, 0xFD, 0x56, 0xCC, 0x53, 0x7E, 0xE0, 0x58
};

const unsigned char iv_seed[] = {
	0x43, 0x35, 0xAB, 0x3D, 0x40, 0xB2, 0x81, 0x7A, 0xA6, 0xEC, 0x46, 0xF3, 0x47, 0xFF, 0x63, 0x3B
};

void ref00d_aes_cbc_decrypt(SceAesContext *ctx, const void *src, void *dst, int length, void *iv);

int ref00dAesCbcDecrypt(const void *src, void *dst, int length, const void *key, SceSize keysize, void *iv){

	SceAesContext ctx;
	memset(&ctx, 0, sizeof(ctx));

	if((length & 0xF) != 0)
		return -1;

	ksceAesInit1(&ctx, 128, keysize, key);
	ref00d_aes_cbc_decrypt(&ctx, src, dst, length, iv);

	return 0;
}

int kprxAuthDecryptKey(SceKprxAuthKey *entry){

	int res;
	unsigned char iv[0x10];
	SceKprxAuthKey tmp;
	ScePortabilityData src, dst;

	memcpy(&tmp, entry, sizeof(tmp));
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));

	src.msg_size = 0x20;
	dst.msg_size = 0x20;

	memcpy(src.msg, tmp.key, 0x20);
	memcpy(iv, iv_seed, sizeof(iv));

	res = ksceSblSsDecryptWithPortability(1, iv, &src, &dst);
	if(res < 0)
		return res;

	memcpy(tmp.key, dst.msg, 0x20);
	memcpy(iv, iv_seed, sizeof(iv));

	res = ref00dAesCbcDecrypt(&tmp, &tmp, sizeof(SceKprxAuthKey), key_seed, 256, iv);
	if(res < 0)
		return res;

	if(tmp.magic != 0x0D0F33B9)
		return -1;

	uint32_t sha256_res[8];

	res = ksceSha256Digest(&tmp, sizeof(SceKprxAuthKey) - sizeof(uint32_t), sha256_res);
	if(res < 0)
		return res;

	if(tmp.hash != (((sha256_res[0] ^ sha256_res[1]) & ~sha256_res[2]) ^ sha256_res[3]))
		return -1;

	tmp.hash = 0;

	ksceKernelCpuUnrestrictedMemcpy(entry, &tmp, sizeof(SceKprxAuthKey));

	return 0;
}

int kprxAuthKeysSetup(void){

	int res;

	for(int i=0;i<REF00D_KPRX_AUTH_KEY_NUMBER;i++){
		res = kprxAuthDecryptKey((SceKprxAuthKey *)&kprx_auth_key_list[i]);
		if(res < 0)
			return res;
	}

	return 0;
}

int kprxAuthCheckSystemFw(void){

	SceKblParam *pKblParam = ksceKernelSysrootGetKblParam();
	if(pKblParam == NULL)
		return -1;

	if(((pKblParam->current_fw_version & ~0xFFF) - 0x3600000) >= 0x140000)
		return -1;

	return 0;
}

int ref00d_kprx_auth_initialization(void){

	int res;

	res = kprxAuthCheckSystemFw();
	if(res < 0){
		printf("%s:kprxAuthCheckSystemFw failed 0x%X\n", __FUNCTION__, res);
		return res;
	}

	SceUID SceNpDrm_moduleid = ksceKernelSearchModuleByName("SceNpDrm");
	if(SceNpDrm_moduleid < 0){
		printf("%s:SceNpDrm not found.\n", __FUNCTION__);
		return SceNpDrm_moduleid;
	}

	res = module_get_offset(0x10005, SceNpDrm_moduleid, 0, 0xEDD4 | 1, (uintptr_t *)&sceNpDrmRsaModPower);
	if(res < 0)
		return res;

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

static int get_key(int key_type, uint16_t sce_type, uint64_t sys_ver, int key_rev, int selftype, int flags){
	for(int i = 0; i < REF00D_KPRX_AUTH_KEY_NUMBER; i++){
		if(
			(kprx_auth_key_list[i].flags     == flags) &&
			(kprx_auth_key_list[i].self_type == selftype) && (kprx_auth_key_list[i].key_rev  == key_rev) &&
			(kprx_auth_key_list[i].key_type  == key_type) && (kprx_auth_key_list[i].sce_type == sce_type) &&
			(sys_ver >= kprx_auth_key_list[i].minver) && (sys_ver <= kprx_auth_key_list[i].maxver)
		){
			return i;
		}
	}
	return -1;
}

int remove_npdrm_personalize(cf_header *cf_hdr, const void *key, const void *klicensee){

	char klicensee_dec[0x10];
	char iv[0x20];

	void *decrypt_point = &ref00d_private_header[sizeof(cf_header) + cf_hdr->m_ext_header_size];

	memset(&iv, 0, sizeof(iv));

	// klicensee to metadata decrypt key
	ksceSblDmac5AesCbcDec(klicensee, &klicensee_dec, 0x10, key, 0x80, &iv, 1);

	// decrypt metadata
	ksceSblDmac5AesCbcDec(decrypt_point, decrypt_point, sizeof(SceSelfAuthHeaderKey), klicensee_dec, 0x80, &iv[0x10], 1);

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

	ksceSblDmac5AesCbcDec(decrypt_point, decrypt_point, sizeof(SceSelfAuthHeaderKey), key_info->key, 0x100, rw_iv, 1);

	pHeaderKey = decrypt_point;
	decrypt_point += sizeof(SceSelfAuthHeaderKey);

	memcpy(ref00d_private_header_iv, pHeaderKey->iv, 0x10);

	SceSize DecryptSize = cf_hdr->m_header_length - (sizeof(cf_header) + cf_hdr->m_ext_header_size + sizeof(SceSelfAuthHeaderKey));

	ksceSblDmac5AesCbcDec(decrypt_point, decrypt_point, DecryptSize, pHeaderKey->key, 0x80, ref00d_private_header_iv, 1);

	pHeaderInfo = decrypt_point;
	decrypt_point += sizeof(SceSelfAuthHeaderInfo);

	/*
	 * Does PS Vita only support RSA2048(type5)
	 */
	if(pHeaderInfo->sig_type != 5){
		ksceDebugPrintf("unknown sig type : 0x%X\n", pHeaderInfo->sig_type);
		return 0x800F0625;
	}

	if(key_info->rsa_n[0] != 0){

		void *pSelfRsaSig = (void *)(ref00d_private_header + pHeaderInfo->offset_sig);

		__swap_data(pSelfRsaSig, pSelfRsaSig, 0x100); // Big endian to little endian

		char kprx_auth_rsa_buffer_e[0x100];
		memset(kprx_auth_rsa_buffer_e, 0, sizeof(kprx_auth_rsa_buffer_e));
		*(uint32_t *)(kprx_auth_rsa_buffer_e) = 0x10001;

		SceNpDrmRsaKey rsa_keys;

		rsa_keys.n = key_info->rsa_n;
		rsa_keys.k = kprx_auth_rsa_buffer_e;

		int res = sceNpDrmRsaModPower(pSelfRsaSig, pSelfRsaSig, &rsa_keys, 0x40);
		if(res < 0){
			ksceDebugPrintf("sceNpDrmRsaModPower failed\n");
			return 0x800F0516;
		}

		char header_hash[0x20];

		res = ksceSha256Digest(ref00d_private_header, (SceSize)pHeaderInfo->offset_sig, header_hash);
		if(res < 0){
			return 0x800F0616;
		}

		__swap_data(pSelfRsaSig, pSelfRsaSig, 0x20);

		if(memcmp(header_hash, pSelfRsaSig, 0x20) != 0){
			ksceDebugPrintf("Header hash not match on RSA sig and raw header\n");
			return 0x800F0516;
		}
	}

	pSegmentInfo = decrypt_point;
	decrypt_point += (sizeof(SceSelfAuthSegmentInfo) * pHeaderInfo->section_num);

	pKeyBase = decrypt_point;

	return 0;
}

int decrypt_module(const void *header, SceSize header_size, SceSblSmCommContext130 *ctx130){

	int res, key_index;
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
		return 0x800f0624;

	ext_hdr      = (ext_header          *)(&ref00d_private_header[sizeof(cf_header)]);
	appinfo      = (SCE_appinfo         *)(&ref00d_private_header[ext_hdr->appinfo_offset]);
	control_info = (PSVita_CONTROL_INFO *)(&ref00d_private_header[ext_hdr->controlinfo_offset]);

	int next = 0;

	do {
		next = control_info->next & 1;
		switch(control_info->type){
		case 4:
			sysver = control_info->PSVita_elf_digest_info.min_required_fw;
			break;
		case 7:
			memcpy(&self_auth_info.padding2, control_info->PSVita_shared_secret_info.shared_secret_0, 0x10);
			break;
		}
		control_info = (PSVita_CONTROL_INFO *)((char *)control_info + control_info->size);
	} while(next == 1);

	if(sysver == 0LL)
		sysver = appinfo->version;

	if(appinfo->self_type == APP){
		key_index = get_key(NPDRM, cf_hdr->m_category, sysver, (cf_hdr->attributes.m_sdk_type >= 2) ? 1 : 0, appinfo->self_type, 0);
		if(key_index < 0)
			return -1;

		res = remove_npdrm_personalize(cf_hdr, kprx_auth_key_list[key_index].key, &self_auth_info.klicensee);
		if(res < 0)
			return res;
	}

	key_index = get_key(METADATA, cf_hdr->m_category, sysver, cf_hdr->attributes.m_sdk_type, appinfo->self_type, 0);
	if(key_index < 0)
		key_index = get_key(METADATA, cf_hdr->m_category, sysver, cf_hdr->attributes.m_sdk_type, appinfo->self_type, REF00D_KEY_FLAG_HAS_PROTOTYPE);

	if(key_index < 0){
		ksceDebugPrintf(
			"key not found. category:%08X sysver:%llX sdk_type:%X self_type:%X\n",
			cf_hdr->m_category, sysver, cf_hdr->attributes.m_sdk_type, appinfo->self_type
		);
		return -1;
	}

	/*
	 * decrypt and get section
	 */
	res = decrypt_certified_personalize(&kprx_auth_key_list[key_index]);
	if(res < 0){
		ksceDebugPrintf("decrypt_certified_personalize failed.\n");
		return res;
	}

	const SceSelfAuthMetaInfo *pMetaInfo = (const SceSelfAuthMetaInfo *)(((uintptr_t)pKeyBase) + (pHeaderInfo->seg_keys_area_size * 0x10));

	do {
		next = pMetaInfo->next & 1;
		switch(pMetaInfo->type){
		case 1:
			memcpy(&self_auth_info.capability, &pMetaInfo->PSVITA_caps_info.capability, sizeof(self_auth_info.capability));
			break;
		case 3:
			memcpy(&self_auth_info.attributes, &pMetaInfo->PSVITA_attr_info.attributes, sizeof(self_auth_info.attributes));
			break;
		}
		pMetaInfo = (SceSelfAuthMetaInfo *)(((uintptr_t)pMetaInfo) + pMetaInfo->size);
	} while(next == 1);

	if(appinfo->self_type >= 0x10000){

		int ac_val = check_ac(&self_auth_info.attributes, 29);

		if(ksceSblAimgrIsDEX() != 0 && ac_val == 0){
			ksceDebugPrintf("[%-15s] %s : %s = %d\n", "Error", "System product", "DEX", ksceSblAimgrIsDEX());
			return 0x800F0516;
		}

		ac_val = check_ac(&self_auth_info.attributes, 30);

		if(ksceSblAimgrIsTest() != 0 && ac_val == 0){
			ksceDebugPrintf("[%-15s] %s : %s = %d\n", "Error", "System product", "Test", ksceSblAimgrIsTest());
			return 0x800F0516;
		}

		if(ksceSblAimgrIsTool() != 0 && ac_val == 0){
			ksceDebugPrintf("[%-15s] %s : %s = %d\n", "Error", "System product", "Tool", ksceSblAimgrIsTool());
			return 0x800F0516;
		}

		ac_val = check_ac(&self_auth_info.attributes, 31);

		if(ksceSblAimgrIsCEX() != 0 && ac_val == 0){
			ksceDebugPrintf("[%-15s] %s : %s = %d\n", "Error", "System product", "CEX", ksceSblAimgrIsCEX());
			return 0x800F0516;
		}

		uint8_t is_production_mode = 0;

		kscePmMgrGetProductMode(&is_production_mode);

		ac_val = check_ac(&self_auth_info.attributes, 32); // Requires production mode
		if(ac_val != 0 && is_production_mode == 0){
			ksceDebugPrintf("[%-15s] %s : %s = %d\n", "Error", "Manufacturing mode", "Required", 1);
			return 0x800F0516;
		}

		ac_val = check_ac(&self_auth_info.attributes, 33); // Prohibit production mode
		if(ac_val != 0 && is_production_mode != 0){
			ksceDebugPrintf("[%-15s] %s : %s = %d\n", "Error", "Manufacturing mode", "Required", 0);
			return 0x800F0516;
		}
	}

	self_auth_info.program_authority_id = appinfo->authid;

	memcpy(&ctx130->self_auth_info, &self_auth_info, sizeof(SceSelfAuthInfo));

	return 0;
}

int ref00d_wait_sema(void){
	int res;

	printf("ref00d_wait_sema start\n");

	res = ksceKernelWaitSema(semaid, 1, NULL);
	if(res > 0)
		res = 0;

	printf("ref00d_wait_sema end\n");

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

	printf("ref00d_auth_close SignalSema start\n");

	res = ksceKernelSignalSema(semaid, 1);
	if(res > 0)
		res = 0;

	printf("ref00d_auth_close SignalSema end\n");

	return res;
}

int ref00d_auth_header(int ctx, const void *header, SceSize header_size, SceSblSmCommContext130 *ctx130){

	int res;

	if(ctx != 1){
		printf("ref00d_auth_header : 0x800F0624\n");
		return 0x800F0624;
	}

	res = decrypt_module(header, header_size, ctx130);

	is_auth_success = ((res >> 0x1F) ^ 1) & 1;

	printf("decrypt_module : 0x%X, is_auth_success %X\n", res, is_auth_success);
	return res;
}

int ref00d_load_block(int ctx, void *buffer, SceSize len){

	if((ctx != 1) || (is_auth_success == 0)){
		printf("ref00d_load_block : 0x800F0624\n");
		return 0x800F0624;
	}

	if(pSegmentInfo[currentKey].section_encryption == AES128CTR){
		printf("ref00d_load_block 0x%X, 0x%X\n", buffer, len);

		const void *key = (const void *)(((uintptr_t)pKeyBase) + (pSegmentInfo[currentKey].section_key_idx * 0x10));

		ksceSblDmac5AesCtrDec(buffer, buffer, len, key, 0x80, ref00d_private_iv, 1);
	}else{
		printf("ref00d_load_block not supported format\n");
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

			printf("ref00d_setup_segment\n");
			printf("found key idx : 0x%X\n", i);

			currentKey = i;

			const void *iv = (pKeyBase + (pSegmentInfo[currentKey].section_iv_idx * 0x10));

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
