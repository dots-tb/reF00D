//reF00D - by the FAPS TEAM
// the French - @Celesteblue123 - vita REV ur ENGS to the MAX
// the American - @dots_tb - ref00d  for games and at runtime with """optimizations"""
// the 【﻿Ｐｒｉｎｃｅｓｓ　ｏｆ　Ｓｌｅｅｐｉｎｇ】 - @PoSsvkey  - for Module decryption on Vita PoC and cleaning up my terrible code.

// With @juliosueiras and TheRadziu - @AluProductions

// Special thanks:
// to Team Molecule for feeding the p00r. 
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

typedef struct {
  uint16_t version;                 // 0x00
  uint16_t version_flag;            // 0x02
  uint16_t type;                    // 0x04
  uint16_t flags;                   // 0x06
  uint64_t aid;                     // 0x08
  char content_id[0x30];            // 0x10
  uint8_t key_table[0x10];          // 0x40
  uint8_t key[0x10];                // 0x50
  uint64_t start_time;              // 0x60
  uint64_t expiration_time;         // 0x68
  uint8_t ecdsa_signature[0x28];    // 0x70

  uint64_t flags2;                  // 0x98
  uint8_t key2[0x10];               // 0xA0
  uint8_t unk_B0[0x10];             // 0xB0
  uint8_t openpsid[0x10];           // 0xC0
  uint8_t unk_D0[0x10];             // 0xD0
  uint8_t cmd56_handshake[0x14];    // 0xE0
  uint32_t unk_F4;                  // 0xF4
  uint32_t unk_F8;                  // 0xF8
  uint32_t sku_flag;                // 0xFC
  uint8_t rsa_signature[0x100];     // 0x100
} SceNpDrmLicense;

int ksceNpDrmGetRifName(char *name, int ignored, uint64_t aid);
int ksceNpDrmGetFixedRifName(char *rif_name, uint32_t flags, uint64_t is_gc);
int ksceNpDrmGetRifVitaKey(SceNpDrmLicense *license_buf, uint8_t *klicensee, uint32_t *flags, uint32_t *sku_flag, uint64_t *start_time, uint64_t *expiration_time);

#define printf ksceDebugPrintf
#define HOOKS_NUMBER 5

#define DEVICES_AMT 4

const char *DEVICES[DEVICES_AMT]= {"ux0:", "ur0:", "gro0:", "grw0:"};

static int hooks_uid[HOOKS_NUMBER];
static tai_hook_ref_t ref_hooks[HOOKS_NUMBER];

#define GetExport(modname, lib_nid, func_nid, func) \
	module_get_export_func(KERNEL_PID, modname, lib_nid, func_nid, (uintptr_t *)func)

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

int (* sceSblSsMgrAESCBCDecryptForDriver)(void *src, void *dst, int size, void *key, int key_size, void *iv, int mask_enable);
void *(*sceSysmemMallocForKernel)(size_t size);
int (*sceSysmemFreeForKernel)(void *ptr);

#define REF00D_KEYS "ur0:/tai/keys.bin"

typedef struct KeyHeader {
	uint32_t magic;
	uint32_t num_of_keys;
	uint32_t key_size;
} KeyHeader;

int getlicensee_rif(char *path, char *klicensee) {
	int res, fd;
	char *klicensee_buf = NULL, *klicensee_buf_aligned;
	klicensee_buf = sceSysmemMallocForKernel(0x200 + 63);
	klicensee_buf_aligned = (char *)(((int)klicensee_buf + 63) & 0xFFFFFFC0);
	memset(klicensee, 0, 0x10);
	fd = ksceIoOpen(path, SCE_O_RDONLY, 0);
	ksceIoRead(fd, klicensee_buf_aligned, 0x200);
	ksceIoClose(fd);
	res = ksceNpDrmGetRifVitaKey((SceNpDrmLicense *)klicensee_buf_aligned, (uint8_t *)klicensee, NULL, NULL, NULL, NULL);
	sceSysmemFreeForKernel(klicensee_buf);
	return res;
}

typedef struct SceKey {
	KeyType key_type;
	SceType sce_type;
	uint8_t key_rev;
	char key[0x100];
	char iv[0x10];
	SelfType self_type;
	uint64_t minver;
	uint64_t maxver;
} SceKey;

static int current_key = 0;
static SceKey KEYS[24];

void register_key(KeyType key_type, SceType sce_type, uint16_t key_rev, char *key, char *iv, uint64_t minver, uint64_t maxver, SelfType selftype) {
	KEYS[current_key].key_type = key_type;
	KEYS[current_key].sce_type = sce_type;
	KEYS[current_key].key_rev = key_rev;
	memcpy(&KEYS[current_key].key, key, sizeof(KEYS[current_key].key));
	memcpy(&KEYS[current_key].iv, iv, sizeof(KEYS[current_key].iv));
	KEYS[current_key].minver = minver;
	KEYS[current_key].maxver = maxver;
	KEYS[current_key++].self_type = selftype;	
}

int get_key(KeyType key_type,  SceType sce_type, uint64_t sys_ver, int key_rev, SelfType selftype) {
	
	for(int i = 0; i < current_key; i++) {
		if(KEYS[i].key_type == key_type && 
			KEYS[i].sce_type == sce_type &&
			KEYS[i].self_type == selftype &&
			KEYS[i].key_rev == key_rev &&
			sys_ver >= KEYS[i].minver &&
			sys_ver <= KEYS[i].maxver)
				return i;
	}
	return -1;
}



void authid2titleid(uint64_t *authid, char *titleid) { // CelesteBlue 
	if (((((char*)authid)[2] >> 1) & 0x1E) == 0)
		snprintf(titleid, 10, "NPXS"); // "NPXS" case
	 else { 
		snprintf(titleid, 10, "PCS%c", 0x41 + (((((char*)authid)[2] >> 1) - 1)  & 0x1F)); // "PCS" case
		snprintf(titleid+4, 10,  "%05d", (int)(((uint32_t*)authid)[0] & 0x1FFFF)); // number
	}
}

static ModuleMetadataDecKeyInfo_t MetadataDecKeyInfo;
static ModuleMetadataHeader_t MetadataHeader;
static ModuleMetadataKeyInfo_t MetadataKeyInfo[5];
static ModuleSectionOffsetInfo_t SectionOffsetInfo[5];
static SceSelfAuthInfo self_auth;

static int doDecrypt = 0, currentKey = 0, currentSeg = 0;
static SceAesContext scectx;

static int decrypt_module(char *header, int header_size, SceSblSmCommContext130 *context_130, char *path_buf_aligned, char *read_buf_aligned) {
	int ret;

	char iv[0x10];
	memset(&iv, 0, sizeof(iv));

	SCE_header *shdr = (SCE_header *)header;
	SCE_appinfo *appinfo = (SCE_appinfo *)(header + shdr->appinfo_offset);
	segment_info *seg_info = (segment_info *)(header + shdr->section_info_offset);
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)(header + shdr->elf_offset);

	int i = 0;
	while(i < ehdr->e_phnum && seg_info[i].encryption != 1) 
		i++;
	
	if(i == ehdr->e_phnum)
		return -1;

	int offset = shdr->metadata_offset + 0x30;
	char *meta_data_buf = header + offset;
	offset += 0x40;
	uint64_t sysver = -1;
	PSVita_CONTROL_INFO *control_info = (PSVita_CONTROL_INFO *)(header + shdr->controlinfo_offset);
	while(control_info->next) {
		switch(control_info->type) {
			case 4:
				sysver = control_info->PSVita_elf_digest_info.min_required_fw;
				sysver = sysver << 32;
				break;
		}
		control_info = (PSVita_CONTROL_INFO*)((char*)control_info + control_info->size);
	}
	if(sysver<=0) 
		sysver = appinfo->version;

	if(appinfo->self_type == APP) {
		char klicensee[0x10];
		char klicensee_dec[0x10];
		int keytype = shdr->sdk_type >= 2 ? 1 : 0;
		
		int np_key_index = get_key(NPDRM, shdr->header_type, sysver, keytype, appinfo->self_type);
		if(np_key_index < 0)
			return np_key_index;	
		
		char titleid[32];
		authid2titleid(&appinfo->authid, titleid);
		
		uint64_t aid;
		
		ksceRegMgrGetKeyBin("/CONFIG/NP", "account_id", &aid, sizeof(uint64_t));
		for(int i = 0; i < DEVICES_AMT; i++){

			if(strncmp(DEVICES[i], "gr", 2) == 0 ){

				ksceNpDrmGetFixedRifName(path_buf_aligned + 512, 0, 1LL);
				snprintf(path_buf_aligned, 512, "%s/license/app/%s/%s", DEVICES[i], titleid, path_buf_aligned + 512);
				if((ret = getlicensee_rif(path_buf_aligned, klicensee)) >= 0)
					break;

			} else {

				ksceNpDrmGetRifName(path_buf_aligned + 512, 0, aid);
				snprintf(path_buf_aligned, 512, "%s/license/app/%s/%s", DEVICES[i], titleid, path_buf_aligned + 512);
				if((ret = getlicensee_rif(path_buf_aligned, klicensee)) >= 0)
					break;

				ksceNpDrmGetRifName(path_buf_aligned + 512, 0, 0LL);
				snprintf(path_buf_aligned, 512, "%s/license/app/%s/%s", DEVICES[i], titleid, path_buf_aligned + 512);
				if((ret = getlicensee_rif(path_buf_aligned, klicensee)) >= 0)
					break;

				ksceNpDrmGetFixedRifName(path_buf_aligned + 512, 0, 0LL);
				snprintf(path_buf_aligned, 512, "%s/license/app/%s/%s", DEVICES[i], titleid, path_buf_aligned + 512);
				if((ret = getlicensee_rif(path_buf_aligned, klicensee)) >= 0)
					break;
			}
		}

		if(ret < 0)
			return ret;
		
		memset(&iv, 0, sizeof(iv) );
		ret = sceSblSsMgrAESCBCDecryptForDriver(&klicensee, &klicensee_dec, 0x10, &(KEYS[np_key_index].key), 0x80, &iv, 1);
		if(ret < 0)
			return ret;
		
		memset(&iv, 0, sizeof(iv) );
		ret = sceSblSsMgrAESCBCDecryptForDriver(meta_data_buf, read_buf_aligned, 0x40, klicensee_dec, 0x80, &iv, 1);
		if(ret < 0)
			return ret;

		meta_data_buf = read_buf_aligned;
	}
	
	memset(&iv, 0, sizeof(iv) );
	
	int key_index = get_key(METADATA, shdr->header_type, sysver, shdr->sdk_type, appinfo->self_type);
	if(key_index < 0)
		return key_index;
	memcpy(&iv, &(KEYS[key_index].iv), 0x10);
	
	ret = sceSblSsMgrAESCBCDecryptForDriver(meta_data_buf, &MetadataDecKeyInfo, 0x40, &(KEYS[key_index].key), 0x100, &iv, 1);
	if(ret < 0)
		return ret;
	
	#define DecryptMetadata(src, len, dst, add) \
		sceSblSsMgrAESCBCDecryptForDriver(src,  dst, len, &MetadataDecKeyInfo.key, 0x80, &MetadataDecKeyInfo.iv, 1); \
		offset += add ? len : 0
		
	DecryptMetadata(header + offset, sizeof(ModuleMetadataHeader_t), &MetadataHeader, 1);
	if(MetadataHeader.sig_type != 5)
		return -1;

	DecryptMetadata(header + offset, (sizeof(ModuleSectionOffsetInfo_t) * MetadataHeader.section_num), &SectionOffsetInfo, 1);
	DecryptMetadata(header + offset,  sizeof(ModuleMetadataKeyInfo_t) * MetadataHeader.section_num, &MetadataKeyInfo, 1);

	char *meta_buf = NULL, *meta_buf_aligned;
	if(header_size - offset > 0x1000)
		return -1;
	meta_buf = sceSysmemMallocForKernel(header_size - offset + 63);
	meta_buf_aligned = (char *)(((int)meta_buf + 63) & 0xFFFFFFC0);

	DecryptMetadata(header + offset,   header_size - offset , meta_buf_aligned, 0);
	
	PSVITA_METADATA_INFO *meta_info = (PSVITA_METADATA_INFO *)meta_buf_aligned;
	while(offset < header_size) {
		switch(meta_info->type) {
			case 1:
				memcpy(&self_auth.capability, &meta_info->PSVITA_caps_info.capability, sizeof(self_auth.capability));
				break;
			case 3:
				memcpy(&self_auth.attribute, &meta_info->PSVITA_attrs_info.attribute, sizeof(self_auth.attribute));
				break;
		}
		if(meta_info->next) {
			offset += meta_info->size;
			meta_info = (PSVITA_METADATA_INFO*)((char*)meta_info + meta_info->size);
		} else
			break;
	}
	
	sceSysmemFreeForKernel(meta_buf);
	
	self_auth.program_authority_id = context_130->self_auth_info.program_authority_id;
	doDecrypt = 1;
	currentSeg = 0;
	
	Elf32_Phdr *phdr = (Elf32_Phdr *)(header + shdr->phdr_offset);
	for(int i = 0; i < MetadataHeader.section_num; i++) {
		if(SectionOffsetInfo[i].section_idx==currentSeg) 
			currentKey = i;
		if(phdr[SectionOffsetInfo[i].section_idx].p_type == 0x6fffff01)
			SectionOffsetInfo[i].section_size = 0;
	}
	
	memset(&scectx, 0, sizeof(scectx));
	ksceAesInit1(&scectx, 0x80, 0x80, &MetadataKeyInfo[currentKey].key);

	return 0;
}

static int ksceSblAuthMgrAuthHeaderForKernel_patched(int ctx, char *header, int header_size, SceSblSmCommContext130 *context_130){
	int ret = -1, state;
	ENTER_SYSCALL(state);
	ret = TAI_CONTINUE(int, ref_hooks[3], ctx, header, header_size, context_130);
	doDecrypt = 0;
	if(ret < 0) {
		
		char *path_buf = NULL, *path_buf_aligned;
		path_buf = sceSysmemMallocForKernel(1024 + 63);
		path_buf_aligned = (char *)(((int)path_buf + 63) & 0xFFFFFFC0);		
		
		char *read_buf = NULL, *read_buf_aligned;
		read_buf = sceSysmemMallocForKernel(0x40 + 63);
		read_buf_aligned = (char *)(((int)read_buf + 63) & 0xFFFFFFC0);
		
		decrypt_module(header, header_size, context_130, path_buf_aligned, read_buf_aligned);
		
		sceSysmemFreeForKernel(path_buf);
		sceSysmemFreeForKernel(read_buf);
	}

	SCE_header *shdr = (SCE_header *)header;
	SCE_appinfo *appinfo = (SCE_appinfo *)(header + shdr->appinfo_offset);	
	if(context_130->self_auth_info_caller.program_authority_id  == self_auth.program_authority_id || appinfo->authid   == self_auth.program_authority_id) 
		memcpy((char*)(context_130->self_auth_info.capability), (char*)&self_auth + 0x10, 0x40);
	
	EXIT_SYSCALL(state);
	return ret;
}

void aes_128_ctr_decrypt_seg(uint8_t *src, int length){
	uint8_t buffer[0x10];
	uint8_t buffer_enc[0x10];
	unsigned i;
	int bi;
	for (i = 0, bi = 0x10; i < length; ++i, ++bi) {
		if (bi == 0x10) {/* we need to regen xor compliment in buffer */

			memcpy(buffer, &MetadataKeyInfo[currentKey].iv, 0x10);
			ksceAesEncrypt1(&scectx, &buffer, &buffer_enc);
			memcpy(buffer, buffer_enc, 0x10);
			/* Increment Iv and handle overflow */
			for (bi = (0x10 - 1); bi >= 0; --bi) {
				/* inc will owerflow */
				if (MetadataKeyInfo[currentKey].iv[bi] == 255) {
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

static int decrypt_buffer_patched(int ctx, void *buffer, size_t len) {
	int ret, state;
	ENTER_SYSCALL(state);
	ret = TAI_CONTINUE(int, ref_hooks[1], ctx, buffer, len);

	if(doDecrypt && ret < 0) {
		while(SectionOffsetInfo[currentKey].section_size <=0 && currentKey < MetadataHeader.section_num) {
			currentSeg++;
			for(int i = 0; i < MetadataHeader.section_num; i++) {
				if(SectionOffsetInfo[i].section_idx==currentSeg) 
					currentKey = i;
				
			}
			memset(&scectx, 0, sizeof(scectx));
			ksceAesInit1(&scectx, 0x80, 0x80, &MetadataKeyInfo[currentKey].key);
			
		}
		if(currentKey < MetadataHeader.section_num) {
			aes_128_ctr_decrypt_seg(buffer, len);
			SectionOffsetInfo[currentKey].section_size -= len;
			ret = 0;
		}
	}
	EXIT_SYSCALL(state);
	return ret;
}

static int ksceIoOpen_patched(const char *filename, int flag, SceIoMode mode) {
	int ret = -1, state;
	ENTER_SYSCALL(state);
	
	if((flag & SCE_O_WRONLY) != SCE_O_WRONLY && hooks_uid[3] <= 0 && strstr(filename, "henkaku.suprx") != NULL)
				hooks_uid[3] = taiHookFunctionImportForKernel(KERNEL_PID, &ref_hooks[3], "SceKernelModulemgr", TAI_ANY_LIBRARY, 0xF3411881, ksceSblAuthMgrAuthHeaderForKernel_patched);
	
	if(ret <= 0) ret = TAI_CONTINUE(int, ref_hooks[0], filename, flag, mode);
	EXIT_SYSCALL(state);
	return ret;
}


void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args){
	if(GetExport("SceSysmem", 0x63A519E5, 0xC0A4D2F3, &sceSysmemMallocForKernel) < 0) {
		if(GetExport("SceSysmem", TAI_ANY_LIBRARY, 0x85571907, &sceSysmemMallocForKernel) < 0)
			return SCE_KERNEL_START_FAILED;
	}
	if(GetExport("SceSysmem", 0x63A519E5, 0xABAB0FAB, &sceSysmemFreeForKernel) < 0) {
		if(GetExport("SceSysmem", TAI_ANY_LIBRARY, 0x4233C16D, &sceSysmemFreeForKernel) < 0)
			return SCE_KERNEL_START_FAILED;	
	}
		
	if(GetExport("SceSblSsMgr", TAI_ANY_LIBRARY, 0x121FA69F, &sceSblSsMgrAESCBCDecryptForDriver) < 0)
		return SCE_KERNEL_START_FAILED;	
	
	if((hooks_uid[0] = taiHookFunctionImportForKernel(KERNEL_PID, &ref_hooks[0], "SceKernelModulemgr", TAI_ANY_LIBRARY, 0x75192972, ksceIoOpen_patched)) < 0)
		return SCE_KERNEL_START_FAILED;	
	
	if((hooks_uid[1] = taiHookFunctionImportForKernel(KERNEL_PID, &ref_hooks[1], "SceKernelModulemgr", TAI_ANY_LIBRARY, 0xBC422443, decrypt_buffer_patched)) < 0)
		return SCE_KERNEL_START_FAILED;	

	SceUID fd = ksceIoOpen(REF00D_KEYS, SCE_O_RDONLY, 0);
	if (fd >= 0) {
		KeyHeader hdr;
		ksceIoRead(fd, &hdr, sizeof(KeyHeader));
		if(hdr.magic == 0x53504146)  {
			current_key = hdr.num_of_keys;
			ksceIoRead(fd, &KEYS, hdr.key_size*current_key);
		}
		ksceIoClose(fd);
	}
	
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args){

	return SCE_KERNEL_STOP_SUCCESS;
}
