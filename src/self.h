#pragma once

#include <inttypes.h>

// some info taken from the wiki, see http://vitadevwiki.com/index.php?title=SELF_File_Format

#pragma pack(push, 1)
typedef struct {
	uint32_t magic;                 /* 53434500 = SCE\0 */
	uint32_t version;               /* header version 3*/
	uint8_t platform;              /* */
	uint8_t sdk_type;              /* */
	uint16_t header_type;           /* 1 self, 2 unknown, 3 pkg */
	uint32_t metadata_offset;       /* metadata offset */
	uint64_t header_len;            /* self header length */
	uint64_t elf_filesize;          /* ELF file length */
	uint64_t self_filesize;         /* SELF file length */
	uint64_t unknown;               /* UNKNOWN */
	uint64_t self_offset;           /* SELF offset */
	uint64_t appinfo_offset;        /* app info offset */
	uint64_t elf_offset;            /* ELF #1 offset */
	uint64_t phdr_offset;           /* program header offset */
	uint64_t shdr_offset;           /* section header offset */
	uint64_t section_info_offset;   /* section info offset */
	uint64_t sceversion_offset;     /* version offset */
	uint64_t controlinfo_offset;    /* control info offset */
	uint64_t controlinfo_size;      /* control info size */
	uint64_t padding;
} SCE_header;

typedef struct {
	uint64_t authid;                /* auth id */
	uint32_t vendor_id;             /* vendor id */
	uint32_t self_type;             /* app type */
	uint64_t version;               /* app version */
	uint64_t padding;               /* UNKNOWN */
} SCE_appinfo;

typedef struct {
	uint32_t unk1;
	uint32_t unk2;
	uint32_t unk3;
	uint32_t unk4;
} SCE_version;

typedef struct {
	uint32_t type; // 4==PSVita ELF digest info; 5==PSVita NPDRM info; 6==PSVita boot param info; 7==PSVita shared secret info
	uint32_t size;
	uint64_t next; // 1 if another Control Info structure follows else 0
	union {
		// type 4, 0x50 bytes
		struct  { // 0x40 bytes of data
			uint8_t constant[0x14]; // same for every PSVita/PS3 SELF, hardcoded in make_fself.exe: 627CB1808AB938E32C8C091708726A579E2586E4
			uint8_t elf_digest[0x20]; // on PSVita: SHA-256 of source ELF file, on PS3: SHA-1
			uint8_t padding[8];
			uint32_t min_required_fw; // ex: 0x363 for 3.63
		} PSVita_elf_digest_info;
		// type 5, 0x110 bytes
		struct { // 0x80 bytes of data
			uint32_t magic;               // 7F 44 52 4D (".DRM")
			uint32_t finalized_flag;      // ex: 80 00 00 01
			uint32_t drm_type;            // license_type ex: 2 local, 0XD free with license
			uint32_t padding;
			uint8_t content_id[0x30];
			uint8_t digest[0x10];         // ?sha-1 hash of debug self/sprx created using make_fself_npdrm?
			uint8_t padding_78[0x78];
			uint8_t hash_signature[0x38]; // unknown hash/signature
		} PSVita_npdrm_info;
		// type 6, 0x110 bytes
		struct { // 0x100 bytes of data
			uint32_t is_used; // 0=false, 1=true
			uint8_t boot_param[0x9C]; // ex: starting with 02 00 00 00
		} PSVita_boot_param_info;
		// type 7, 0x50 bytes
		struct { // 0x40 bytes of data
			uint8_t shared_secret_0[0x10]; // ex: 0x7E7FD126A7B9614940607EE1BF9DDF5E or full of zeroes
			uint8_t shared_secret_1[0x10]; // ex: full of zeroes
			uint8_t shared_secret_2[0x10]; // ex: full of zeroes
			uint8_t shared_secret_3[0x10]; // ex: full of zeroes
		} PSVita_shared_secret_info;
	};
} __attribute__((packed)) PSVita_CONTROL_INFO;

typedef struct {
	uint64_t offset;
	uint64_t length;
	uint64_t compression; // 1 = uncompressed, 2 = compressed
	uint64_t encryption; // 1 = encrypted, 2 = plain
} segment_info;

#pragma pack(pop)

enum {
	HEADER_LEN = 0x1000,
	SCE_MAGIC = 0x454353
};

typedef enum SceType {
	SELF = 1,
	SRVK = 2,
	SPKG = 3,
	DEV = 0xC0
} SceType;

typedef enum SceSigType {
	ECDSA160 = 1,
	RSA2048 = 5
} SceSigType;


typedef enum SelfType {
	SELF_NONE = 0,
	KERNEL = 0x07,
	APP = 0x08,
	BOOT = 0x09,
	SECURE = 0x0B,
	USER = 0x0D
} SelfType;

typedef enum KeyType {
	METADATA = 0,
	NPDRM = 1
} KeyType;

typedef enum ControlType {
	CONTROL_FLAGS = 1,
	DIGEST_SHA1 = 2,
	NPDRM_PS3 = 3,
	DIGEST_SHA256 = 4,
	NPDRM_VITA = 5,
	UNK_SIG1 = 6,
	UNK_HASH1 = 7
} ControlType;

typedef enum EncryptionType {
	ENC_NONE = 1,
	AES128CTR = 3
} EncryptionType;

typedef enum HashType{
	HASH_NONE = 1,
	HMACSHA1 = 2,
	HMACSHA256 = 6
} HashType;


typedef struct {
	char key[0x10];
	char off_0x10[0x10];
	char iv[0x10];
	char off_0x30[0x10];
}  __attribute__((packed)) ModuleMetadataDecKeyInfo_t;

typedef struct {
	uint64_t size;
	uint32_t sig_type;
	uint32_t section_num;
    uint32_t seg_keys_area_size; // ex: 0x1E
    uint32_t metadata_infos_area_size; // ex: 0x170
    char padding[8];
}  __attribute__((packed)) ModuleMetadataHeader_t;

typedef struct {
	uint64_t section_start_offset;
	uint64_t section_size;
	uint32_t section_type;
	uint32_t section_idx;
	uint32_t section_hash_type;
	uint32_t section_hash_idx;
	uint32_t section_encryption;
	uint32_t section_key_idx;
	uint32_t section_iv_idx;
	uint32_t section_compression;
}  __attribute__((packed)) ModuleSectionOffsetInfo_t;

typedef struct {
	char SecondSectionHash[0x20];
	char HmacKey[0x20];
	char key[0x10];
	char iv[0x10];
} __attribute__((packed))  ModuleMetadataKeyInfo_t;

typedef struct SceSelfAuthInfo // size is 0x90
{
	SceUInt64 program_authority_id;
	SceUInt64 padding1;
	uint8_t capability[0x20];
	uint8_t attribute[0x20];
	uint8_t padding2[0x10];
	uint8_t klicensee[0x10]; // offset 0x60
	uint32_t unk_70;
	uint32_t unk_74;
	uint32_t unk_78;
	uint32_t unk_7C;
	uint32_t unk_80;
	uint32_t unk_84;
	uint32_t unk_88;
	uint32_t unk_8C;
} SceSelfAuthInfo;

typedef struct SceSblSmCommContext130 // size is 0x130 as its name indicates.
{
	uint32_t unk_0;
	uint32_t self_type; // user = 1 / kernel = 0
	SceSelfAuthInfo self_auth_info_caller; // size is 0x90 - can be obtained with sceKernelGetSelfAuthInfoForKernel
	SceSelfAuthInfo self_auth_info; // size is 0x90
	uint32_t path_id; // can be obtained with sceSblACMgrGetPathIdForKernel or sceIoGetPathIdExForDriver
	uint32_t unk_12C;
} SceSblSmCommContext130;

typedef struct {
  uint32_t type; // 1=caps, 2=unk100, 3=attrs
  uint32_t size;
  uint64_t next; // 1 if another MetaData Info structure follows else 0
  
  union {
    // type 1
    struct { // 0x20 bytes of data
      uint8_t capability[0x20];
    } PSVITA_caps_info;
    
    // type 2
    struct { // 0x100 bytes of data
      uint8_t unk100[0x100];
    } PSVITA_unk100_info;
    
    // type 3
    struct { // 0x20 bytes of data
      uint8_t attribute[0x20];
    } PSVITA_attrs_info;
  };
} __attribute__((packed)) PSVITA_METADATA_INFO;