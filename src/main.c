//reF00D - by the FAPS TEAM
// the French - @Celesteblue123 - vita REV ur ENGS to the MAX
// the American - @dots_tb - ref00d  for games and at runtime with """optimizations"""
// the 【﻿Ｐｒｉｎｃｅｓｓ　ｏｆ　Ｓｌｅｅｐｉｎｇ】 - @PoSsvkey  - for Module decryption on Vita PoC and cleaning up my terrible code.

// With @juliosueiras and TheRadziu - @AluProductions

// Special thanks:
// to Team Molecule for feeding the p00r. 
// To motoharu, aerosoul, TheFloW, xerpi, St4rk, Mathieulh, zecoxao for having reversed a part of the PSVita and made useful tools.
// to Silica for his mental illness (actually caring about PSM) which made us realize the headers weren't always in order. 
// To sys for being sys

// Testing team:
// amadeus
// Samilop Iter
// Thibobo
// Yoti
// Waterflame
// Z3R0

#include <psp2kern/kernel/utils.h>
#include <vitasdkkern.h>

#include <taihen.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "self.h"
#include "elf.h"

#define HookImport(module_name, library_nid, func_nid, func_name) taiHookFunctionImportForKernel(0x10005, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patched)

#define HookRelease(hook_uid, hook_func_name)({ \
	if(hook_uid > 0)taiHookReleaseForKernel(hook_uid, hook_func_name ## _ref); \
})

#define GetExport(modname, lib_nid, func_nid, func) \
	module_get_export_func(KERNEL_PID, modname, lib_nid, func_nid, (uintptr_t *)func)

#define printf ksceDebugPrintf
#define HOOKS_NUMBER 3

#define REF00D_KEYS "ur0:/tai/keys.bin"

#define MAX_KEY_SET 32

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

typedef struct KeyHeader {
	uint32_t magic;
	uint32_t num_of_keys;
	uint32_t key_size;
} KeyHeader;

typedef struct SceKey {
	KeyType key_type;
	SceType sce_type;
	uint8_t key_rev;
	uint8_t key[0x100];
	uint8_t iv[0x10];
	SelfType self_type;
	uint64_t minver;
	uint64_t maxver;
} SceKey;

static int hooks_uid[HOOKS_NUMBER];

static int (* sceSblSsMgrAESCBCDecryptForDriver)(void *src, void *dst, int size, void *key, int key_size, void *iv, int mask_enable);
static void *(*sceSysmemMallocForKernel)(size_t size);
static int (*sceSysmemFreeForKernel)(void *ptr);

static int current_key_num = 0;
static SceKey KEYS[MAX_KEY_SET];

static ModuleMetadataDecKeyInfo_t MetadataDecKeyInfo;
static ModuleMetadataHeader_t MetadataHeader;
static ModuleMetadataKeyInfo_t MetadataKeyInfo[5];
static ModuleSectionOffsetInfo_t SectionOffsetInfo[5];
static SceSelfAuthInfo self_auth;

static int doDecrypt = 0, currentKey = 0, currentSeg = 0;
static SceAesContext scectx;

static tai_hook_ref_t ksceIoOpen_ref;
static tai_hook_ref_t sceSblAuthMgrAuthHeaderForKernel_ref;
static tai_hook_ref_t sceSblAuthMgrLoadBlockForKernel_ref;

void register_key(KeyType key_type, SceType sce_type, uint16_t key_rev, char *key, char *iv, uint64_t minver, uint64_t maxver, SelfType selftype){
	KEYS[current_key_num].key_type = key_type;
	KEYS[current_key_num].sce_type = sce_type;
	KEYS[current_key_num].key_rev = key_rev;
	memcpy(&KEYS[current_key_num].key, key, sizeof(KEYS[current_key_num].key));
	memcpy(&KEYS[current_key_num].iv, iv, sizeof(KEYS[current_key_num].iv));
	KEYS[current_key_num].minver = minver;
	KEYS[current_key_num].maxver = maxver;
	KEYS[current_key_num].self_type = selftype;
	current_key_num++;
}

static int get_key(KeyType key_type,  SceType sce_type, uint64_t sys_ver, int key_rev, SelfType selftype){
	for(int i = 0; i < current_key_num; i++){
		if(
			(KEYS[i].key_type == key_type) && (KEYS[i].sce_type == sce_type) &&
			(KEYS[i].self_type == selftype) && (KEYS[i].key_rev == key_rev) &&
			(sys_ver >= KEYS[i].minver) && (sys_ver <= KEYS[i].maxver)
		){
			return i;
		}
	}
	return -1;
}

static int decrypt_module(char *header, int header_size, SceSblSmCommContext130 *context_130){
	int res = 0;

	char iv[0x10];
	void *npdrmkey = NULL;

	SCE_header *shdr = (SCE_header *)header;
	SCE_appinfo *appinfo = (SCE_appinfo *)(header + shdr->appinfo_offset);
	segment_info *seg_info = (segment_info *)(header + shdr->section_info_offset);
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)(header + shdr->elf_offset);

	int i = 0;
	while(i < ehdr->e_phnum && seg_info[i].encryption != 1) i++;
	
	if(i == ehdr->e_phnum){
		res = -1;
		goto decrypt_end;
	}

	int offset = shdr->metadata_offset + 0x30;
	char *meta_data_buf = header + offset;
	offset += 0x40;
	uint64_t sysver = 0LL;

	PSVita_CONTROL_INFO *control_info = (PSVita_CONTROL_INFO *)(header + shdr->controlinfo_offset);
	while(control_info->next){
		switch(control_info->type){
		case 4:
			sysver = (uint64_t)control_info->PSVita_elf_digest_info.min_required_fw << 32;
			break;
		}
		control_info = (PSVita_CONTROL_INFO*)((char *)control_info + control_info->size);
	}

	if(sysver == 0LL)
		sysver = appinfo->version;

	if(appinfo->self_type == APP){
		char klicensee_dec[0x10];

		npdrmkey = sceSysmemMallocForKernel(0x40);

		int np_key_index = get_key(NPDRM, shdr->header_type, sysver, (shdr->sdk_type >= 2) ? 1 : 0, appinfo->self_type);
		if(np_key_index < 0){
			res = np_key_index;
			goto decrypt_end;
		}

		memset(&iv, 0, sizeof(iv));
		sceSblSsMgrAESCBCDecryptForDriver(&(context_130->self_auth_info.klicensee), &klicensee_dec, 0x10, &(KEYS[np_key_index].key), 0x80, &iv, 1);

		memset(&iv, 0, sizeof(iv));
		sceSblSsMgrAESCBCDecryptForDriver(meta_data_buf, npdrmkey, 0x40, klicensee_dec, 0x80, &iv, 1);

		meta_data_buf = npdrmkey;
	}

	memset(&iv, 0, sizeof(iv));

	int key_index = get_key(METADATA, shdr->header_type, sysver, shdr->sdk_type, appinfo->self_type);
	if(key_index < 0){
		res = key_index;
		goto decrypt_end;
	}

	memcpy(&iv, &(KEYS[key_index].iv), 0x10);

	sceSblSsMgrAESCBCDecryptForDriver(meta_data_buf, &MetadataDecKeyInfo, 0x40, &(KEYS[key_index].key), 0x100, &iv, 1);

	#define DecryptMetadata(src, len, dst, add) \
		sceSblSsMgrAESCBCDecryptForDriver(src, dst, len, &MetadataDecKeyInfo.key, 0x80, &MetadataDecKeyInfo.iv, 1); \
		offset += add ? len : 0

	DecryptMetadata(header + offset, sizeof(ModuleMetadataHeader_t), &MetadataHeader, 1);
	if(MetadataHeader.sig_type != 5){
		res = -1;
		goto decrypt_end;
	}

	DecryptMetadata(header + offset, (sizeof(ModuleSectionOffsetInfo_t) * MetadataHeader.section_num), &SectionOffsetInfo, 1);
	DecryptMetadata(header + offset,  sizeof(ModuleMetadataKeyInfo_t) * MetadataHeader.section_num, &MetadataKeyInfo, 1);

	if((header_size - offset) > 0x1000){
		res = -1;
		goto decrypt_end;
	}

	char *meta_buf = NULL, *meta_buf_aligned;
	meta_buf = sceSysmemMallocForKernel(header_size - offset + 63);
	meta_buf_aligned = (char *)(((int)meta_buf + 63) & 0xFFFFFFC0);

	DecryptMetadata(header + offset, header_size - offset, meta_buf_aligned, 0);

	PSVITA_METADATA_INFO *meta_info = (PSVITA_METADATA_INFO *)meta_buf_aligned;
	while(offset < header_size){
		switch(meta_info->type){
		case 1:
			memcpy(&self_auth.capability, &meta_info->PSVITA_caps_info.capability, sizeof(self_auth.capability));
			break;
		case 3:
			memcpy(&self_auth.attribute, &meta_info->PSVITA_attrs_info.attribute, sizeof(self_auth.attribute));
			break;
		}
		if(meta_info->next){
			offset += meta_info->size;
			meta_info = (PSVITA_METADATA_INFO*)((char*)meta_info + meta_info->size);
		}else{
			break;
		}
	}

	sceSysmemFreeForKernel(meta_buf);

	self_auth.program_authority_id = context_130->self_auth_info.program_authority_id;
	doDecrypt = 1;
	currentSeg = 0;

	Elf32_Phdr *phdr = (Elf32_Phdr *)(header + shdr->phdr_offset);
	for(int i=0;i<MetadataHeader.section_num;i++){
		if(SectionOffsetInfo[i].section_idx == currentSeg) 
			currentKey = i;
		if(phdr[SectionOffsetInfo[i].section_idx].p_type == 0x6fffff01)
			SectionOffsetInfo[i].section_size = 0;
	}

	if((self_auth.program_authority_id == context_130->self_auth_info_caller.program_authority_id) || (self_auth.program_authority_id == appinfo->authid)){
		memcpy((char*)(context_130->self_auth_info.capability), (((char*)&self_auth) + 0x10), 0x40);
	}

	memset(&scectx, 0, sizeof(scectx));
	ksceAesInit1(&scectx, 0x80, 0x80, &MetadataKeyInfo[currentKey].key);

decrypt_end:

	if(npdrmkey != NULL)
		sceSysmemFreeForKernel(npdrmkey);

	return res;
}

static int sceSblAuthMgrAuthHeaderForKernel_patched(int ctx, char *header, int header_size, SceSblSmCommContext130 *context_130){

	int ret, state;
	ENTER_SYSCALL(state);

	ret = TAI_CONTINUE(int, sceSblAuthMgrAuthHeaderForKernel_ref, ctx, header, header_size, context_130);

	if((ret == 0x800F0605) || (ret == 0x800F0616) || ((ret >= 0x800F0B30) && (ret <= 0x800F0B3F))){
		decrypt_module(header, header_size, context_130);
	}else{
		doDecrypt = 0;
	}

	EXIT_SYSCALL(state);
	return ret;
}

static void aes_128_ctr_decrypt_seg(uint8_t *src, int length){
	uint8_t buffer[0x10];
	uint8_t buffer_enc[0x10];
	unsigned i;
	int bi;
	for(i = 0, bi = 0x10; i < length; ++i, ++bi){
		if(bi == 0x10){/* we need to regen xor compliment in buffer */
			memcpy(buffer, &MetadataKeyInfo[currentKey].iv, 0x10);
			ksceAesEncrypt1(&scectx, &buffer, &buffer_enc);
			memcpy(buffer, buffer_enc, 0x10);
			/* Increment Iv and handle overflow */
			for(bi = (0x10 - 1); bi >= 0; --bi){
				/* inc will owerflow */
				if(MetadataKeyInfo[currentKey].iv[bi] == 255){
					MetadataKeyInfo[currentKey].iv[bi] = 0;
					continue;
				} 
				MetadataKeyInfo[currentKey].iv[bi] += 1;
				break;
			}
			bi = 0;
		}
		src[i] = (src[i] ^ buffer[bi]);
	}
}

static int sceSblAuthMgrLoadBlockForKernel_patched(int ctx, void *buffer, size_t len){
	int ret, state;
	ENTER_SYSCALL(state);

	ret = TAI_CONTINUE(int, sceSblAuthMgrLoadBlockForKernel_ref, ctx, buffer, len);

	if(doDecrypt && (ret < 0)){
		while((SectionOffsetInfo[currentKey].section_size <= 0) && (currentKey < MetadataHeader.section_num)){
			currentSeg++;
			for(int i=0;i<MetadataHeader.section_num;i++){
				if(SectionOffsetInfo[i].section_idx == currentSeg) 
					currentKey = i;
			}
			memset(&scectx, 0, sizeof(scectx));
			ksceAesInit1(&scectx, 0x80, 0x80, &MetadataKeyInfo[currentKey].key);
		}
		if(currentKey < MetadataHeader.section_num){
			aes_128_ctr_decrypt_seg(buffer, len);
			SectionOffsetInfo[currentKey].section_size -= len;
			ret = 0;
		}
	}

	EXIT_SYSCALL(state);
	return ret;
}

static int ksceIoOpen_patched(const char *filename, int flag, SceIoMode mode){
	int ret, state;
	ENTER_SYSCALL(state);
	
	if(((flag & SCE_O_WRONLY) == 0) && (hooks_uid[2] <= 0) && (strstr(filename, "henkaku.suprx") != NULL)){
		hooks_uid[2] = HookImport("SceKernelModulemgr", 0x7ABF5135, 0xF3411881, sceSblAuthMgrAuthHeaderForKernel);
	}

	ret = TAI_CONTINUE(int, ksceIoOpen_ref, filename, flag, mode);

	EXIT_SYSCALL(state);
	return ret;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args){

	SceUID fd = 0;
	KeyHeader hdr;

	for(int i=0;i<HOOKS_NUMBER;i++)
		hooks_uid[i] = 0;

	if(GetExport("SceSysmem", 0x63A519E5, 0xC0A4D2F3, &sceSysmemMallocForKernel) < 0)
	if(GetExport("SceSysmem", 0xFFFFFFFF, 0x85571907, &sceSysmemMallocForKernel) < 0)
		goto ref00d_failed;

	if(GetExport("SceSysmem", 0x63A519E5, 0xABAB0FAB, &sceSysmemFreeForKernel) < 0)
	if(GetExport("SceSysmem", 0xFFFFFFFF, 0x4233C16D, &sceSysmemFreeForKernel) < 0)
		goto ref00d_failed;

	if(GetExport("SceSblSsMgr", 0xFFFFFFFF, 0x121FA69F, &sceSblSsMgrAESCBCDecryptForDriver) < 0)
		goto ref00d_failed;

	hooks_uid[0] = HookImport("SceKernelModulemgr", 0xFFFFFFFF, 0x75192972, ksceIoOpen);
	if(hooks_uid[0] < 0)
		goto ref00d_failed;

	hooks_uid[1] = HookImport("SceKernelModulemgr", 0x7ABF5135, 0xBC422443, sceSblAuthMgrLoadBlockForKernel);
	if(hooks_uid[1] < 0)
		goto ref00d_failed;

	fd = ksceIoOpen(REF00D_KEYS, SCE_O_RDONLY, 0);
	if(fd < 0){
		goto ref00d_failed;
	}

	if(ksceIoRead(fd, &hdr, sizeof(KeyHeader)) != sizeof(KeyHeader)){
		goto ref00d_failed;
	}

	if(hdr.magic != 0x53504146){
		goto ref00d_failed;
	}

	if(hdr.num_of_keys > MAX_KEY_SET){
		goto ref00d_failed;
	}

	current_key_num = hdr.num_of_keys;

	ksceIoRead(fd, &KEYS, (hdr.key_size * current_key_num));

	if(fd > 0)
		ksceIoClose(fd);

	return SCE_KERNEL_START_SUCCESS;

ref00d_failed:

	if(fd > 0)
		ksceIoClose(fd);

	HookRelease(hooks_uid[2], sceSblAuthMgrAuthHeaderForKernel);
	HookRelease(hooks_uid[1], sceSblAuthMgrLoadBlockForKernel);
	HookRelease(hooks_uid[0], ksceIoOpen);

	return SCE_KERNEL_START_NO_RESIDENT;
}

int module_stop(SceSize argc, const void *args){

	HookRelease(hooks_uid[2], sceSblAuthMgrAuthHeaderForKernel);
	HookRelease(hooks_uid[1], sceSblAuthMgrLoadBlockForKernel);
	HookRelease(hooks_uid[0], ksceIoOpen);

	return SCE_KERNEL_STOP_SUCCESS;
}
