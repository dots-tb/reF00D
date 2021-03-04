//reF00D - by the FAPS TEAM
// the French - @Celesteblue123 - vita REV ur ENGS to the MAX
// the American - @dots_tb - ref00d for games and at runtime with """optimizations"""
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

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/sysmem.h>
#include <taihen.h>
#include "self.h"
#include "elf.h"
#include "ref00d_types.h"
#include "ref00d_kprx_auth.h"

#define HookExport(module_name, library_nid, func_nid, func_name) taiHookFunctionExportForKernel(0x10005, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patched)
#define HookImport(module_name, library_nid, func_nid, func_name) taiHookFunctionImportForKernel(0x10005, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patched)
#define HookOffset(modid, offset, thumb, func_name) taiHookFunctionOffsetForKernel(0x10005, &func_name ## _ref, modid, 0, offset, thumb, func_name ## _patched)

#define HookRelease(hook_uid, hook_func_name) ({ \
	(hook_uid > 0) ? taiHookReleaseForKernel(hook_uid, hook_func_name ## _ref) : -1; \
})

#define GetExport(modname, lib_nid, func_nid, func) module_get_export_func(KERNEL_PID, modname, lib_nid, func_nid, (uintptr_t *)func)

#define RELEASE 1
#define TEST    0

int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t *addr);
int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

/* ================================ data section ================================ */

extern SceUID semaid;

static int ref00d_ctx;

static tai_hook_ref_t sceSblAuthMgrOpenForKernel_ref;
static tai_hook_ref_t sceSblAuthMgrCloseForKernel_ref;
static tai_hook_ref_t sceSblAuthMgrAuthHeaderForKernel_ref;
static tai_hook_ref_t sceSblAuthMgrLoadBlockForKernel_ref;
static tai_hook_ref_t sceSblAuthMgrLoadSegmentForKernel_ref;

/* ================================ data section ================================ */

#if defined(RELEASE) && (RELEASE == 0)

void hex_dump(const void *addr, int len){

	if(addr == NULL)
		return;

	if(len == 0)
		return;

	for(int i=0;i<len;i+=0x10){
		printf(
			"%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
			((char *)addr)[i + 0x0], ((char *)addr)[i + 0x1], ((char *)addr)[i + 0x2], ((char *)addr)[i + 0x3],
			((char *)addr)[i + 0x4], ((char *)addr)[i + 0x5], ((char *)addr)[i + 0x6], ((char *)addr)[i + 0x7],
			((char *)addr)[i + 0x8], ((char *)addr)[i + 0x9], ((char *)addr)[i + 0xA], ((char *)addr)[i + 0xB],
			((char *)addr)[i + 0xC], ((char *)addr)[i + 0xD], ((char *)addr)[i + 0xE], ((char *)addr)[i + 0xF]
		);
	}
}

#endif

static int sceSblAuthMgrOpenForKernel_patched(int *ctx){

	int ret;

	ret = TAI_CONTINUE(int, sceSblAuthMgrOpenForKernel_ref, ctx);

	ref00d_auth_open(&ref00d_ctx);

	return ret;
}

static int sceSblAuthMgrCloseForKernel_patched(int ctx){
	int ret;

	ret = TAI_CONTINUE(int, sceSblAuthMgrCloseForKernel_ref, ctx);

	ref00d_auth_close(ref00d_ctx);

	return ret;
}

static int sceSblAuthMgrAuthHeaderForKernel_patched(int ctx, const void *header, int header_size, SceSblSmCommContext130 *ctx130){

	int ret, state;
	ENTER_SYSCALL(state);

	ret = ref00d_auth_header(ctx, header, header_size, ctx130);
	if(ret < 0){
		ret = TAI_CONTINUE(int, sceSblAuthMgrAuthHeaderForKernel_ref, ctx, header, header_size, ctx130);
	}

	EXIT_SYSCALL(state);
	return ret;
}

static int sceSblAuthMgrLoadBlockForKernel_patched(int ctx, void *buffer, size_t len){
	int ret, state;
	ENTER_SYSCALL(state);

	if(ref00d_kprx_auth_state() < 0){
		ret = TAI_CONTINUE(int, sceSblAuthMgrLoadBlockForKernel_ref, ctx, buffer, len);
	}else{
		ret = ref00d_load_block(ctx, buffer, len);
	}

	EXIT_SYSCALL(state);
	return ret;
}

static int sceSblAuthMgrLoadSegmentForKernel_patched(int ctx, int seg_idx){
	int ret, state;
	ENTER_SYSCALL(state);

	if(ref00d_kprx_auth_state() < 0){
		ret = TAI_CONTINUE(int, sceSblAuthMgrLoadSegmentForKernel_ref, ctx, seg_idx);
	}else{
		ret = ref00d_setup_segment(ctx, seg_idx);
	}

	EXIT_SYSCALL(state);
	return ret;
}

const SceKernelDebugMessageContext panic_ctx = {
	.hex_value0_hi = 0xA83C06B,
	.hex_value0_lo = 0xE15A014,
	.hex_value1    = 0x1F40730,
	.func = NULL,
	.line = 0,
	.file = NULL
};

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args){

	const void *lr;

	asm volatile("mov %0, lr\n":"=r"(lr));

	semaid = ksceKernelCreateSema("Ref00dSema", 0, 1, 1, NULL);
	if(semaid < 0)
		goto ref00d_failed_end;

	if(ref00d_kprx_auth_initialization() < 0)
		ksceDebugPrintKernelPanic(&panic_ctx, lr);

	HookImport("SceKernelModulemgr", 0x7ABF5135, 0xA9CD2A09, sceSblAuthMgrOpenForKernel);
	HookImport("SceKernelModulemgr", 0x7ABF5135, 0x026ACBAD, sceSblAuthMgrCloseForKernel);
	HookImport("SceKernelModulemgr", 0x7ABF5135, 0xF3411881, sceSblAuthMgrAuthHeaderForKernel);
	HookImport("SceKernelModulemgr", 0x7ABF5135, 0xBC422443, sceSblAuthMgrLoadBlockForKernel);
	HookImport("SceKernelModulemgr", 0x7ABF5135, 0x89CCDA2C, sceSblAuthMgrLoadSegmentForKernel);

	return SCE_KERNEL_START_SUCCESS;

ref00d_failed_end:
	return SCE_KERNEL_START_FAILED;
}
