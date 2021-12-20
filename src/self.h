/*
 * reF00D
 * Copyright (C) 2021, FAPS TEAM
 */

#ifndef _PSP2_SCE_SELF_TYPE_H_
#define _PSP2_SCE_SELF_TYPE_H_

#pragma once

#include <inttypes.h>

// some info taken from the wiki, see http://vitadevwiki.com/index.php?title=SELF_File_Format

typedef struct cf_header {
	uint32_t m_magic;
	uint32_t m_version;
	struct {
		uint8_t m_platform;
		uint8_t m_sdk_type;
	} attributes;
	uint16_t m_category;
	uint32_t m_ext_header_size;

	union {
		uint64_t m_header_length;
		uint64_t m_file_offset;
	};
	uint64_t m_file_size;

	uint64_t m_certified_file_size;
	uint64_t m_padding;
} __attribute__((packed)) cf_header;

typedef struct ext_header {
	// 0x00
	uint64_t self_offset;           /* SELF offset           */
	uint64_t appinfo_offset;        /* app info offset       */

	// 0x10
	uint64_t elf_offset;            /* ELF #1 offset         */
	uint64_t phdr_offset;           /* program header offset */

	// 0x20
	uint64_t shdr_offset;           /* section header offset */
	uint64_t section_info_offset;   /* section info offset   */

	// 0x30
	uint64_t sceversion_offset;     /* version offset        */
	uint64_t controlinfo_offset;    /* control info offset   */

	// 0x40
	uint64_t controlinfo_size;      /* control info size     */
	uint64_t padding;
} ext_header;

typedef struct cf_header_v2 {
	uint32_t m_magic;
	uint32_t m_version;
	struct {
		uint8_t m_platform;
		uint8_t m_sdk_type;
	} attributes;
	uint16_t m_category;
	uint32_t m_ext_header_size;

	union {
		uint64_t m_header_length;
		uint64_t m_file_offset;
	};
	uint64_t m_file_size;
} __attribute__((packed)) cf_header_v2;

typedef struct cf_header_v3 {
	uint32_t m_magic;
	uint32_t m_version;
	struct {
		uint8_t m_platform;
		uint8_t m_sdk_type;
	} attributes;
	uint16_t m_category;
	uint32_t m_ext_header_size;

	union {
		uint64_t m_header_length;
		uint64_t m_file_offset;
	};
	uint64_t m_file_size;

	uint64_t m_certified_file_size;
	uint64_t m_padding;
} __attribute__((packed)) cf_header_v3;

typedef union cf_header_t {
	struct {
		uint32_t m_magic;
		uint32_t m_version;
	} base;
	cf_header_v2 header_v2;
	cf_header_v3 header_v3;
} cf_header_t;

#endif /* _PSP2_SCE_SELF_TYPE_H_ */