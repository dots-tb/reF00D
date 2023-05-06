/*
 * reF00D RSA Engine
 * Copyright (C) 2021, FAPS TEAM
 */

#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/post_ss_mgr.h>
#include "ref00d_types.h"
#include "ref00d_rsa_engine.h"


/* ================================ data section ================================ */

SceUID ref00d_rsa_thid, ref00d_rsa_comm_evfid, ref00d_rsa_mtxid, ref00d_rsa_semaid;
void *rsa_m;
void *rsa_k;
void *rsa_n;
void *rsa_hash;
int rsa_res;

/* ================================ data section ================================ */




#define REF00D_RSA_ENGINE_COMM_REQ      (1 << 0)
#define REF00D_RSA_ENGINE_COMM_REQ_DONE (1 << 1)

int ref00dRsaEngine(SceSize args, void *argp){

	int res;
	unsigned int out_bits;

	while(1){
		res = ksceKernelWaitEventFlag(ref00d_rsa_comm_evfid, REF00D_RSA_ENGINE_COMM_REQ, SCE_EVENT_WAITOR | SCE_EVENT_WAITCLEAR_PAT, &out_bits, NULL);
		if(res < 0){
			continue;
		}

		res = ksceSblRSA2048VerifySignature(
			(SceSblRsaDataParam[]){{.data = rsa_m, .size = 0x100}},
			(SceSblRsaDataParam[]){{.data = rsa_hash, .size = 0x20}},
			(SceSblRsaPublicKeyParam[]){{.n = rsa_n, .k = rsa_k}},
			0xB
		);

		rsa_res = res;

		if(res != SCE_OK){
			rsa_res = 0x800F0024;
		}

		ksceKernelSetEventFlag(ref00d_rsa_comm_evfid, REF00D_RSA_ENGINE_COMM_REQ_DONE);
	}

	return 0;
}

int ref00dRsaEngineRequest(void *src, void *k, void *n, void *hash){

	int res, res_mtx;

	res_mtx = ksceKernelLockMutex(ref00d_rsa_mtxid, 1, NULL);
	if(res_mtx < 0)
		return res_mtx;

	res = ksceKernelWaitSema(ref00d_rsa_semaid, 1, NULL);
	if(res >= 0){
		rsa_m   = src;
		rsa_k   = k;
		rsa_n   = n;
		rsa_hash = hash;

		res = ksceKernelSetEventFlag(ref00d_rsa_comm_evfid, REF00D_RSA_ENGINE_COMM_REQ);
	}

	res_mtx = ksceKernelUnlockMutex(ref00d_rsa_mtxid, 1);
	if(res_mtx < 0)
		res = res_mtx;

	return res;
}

int ref00dRsaEngineWaitWork(void){

	int res, res_mtx, res_sema;

	res_mtx = ksceKernelLockMutex(ref00d_rsa_mtxid, 1, NULL);
	if(res_mtx < 0)
		return res_mtx;

	res = ksceKernelWaitEventFlag(ref00d_rsa_comm_evfid, REF00D_RSA_ENGINE_COMM_REQ_DONE, SCE_EVENT_WAITOR | SCE_EVENT_WAITCLEAR_PAT, NULL, NULL);
	if(res >= 0){
		res = rsa_res;

		res_sema = ksceKernelSignalSema(ref00d_rsa_semaid, 1);
		if(res_sema < 0)
			res = res_sema;
	}

	res_mtx = ksceKernelUnlockMutex(ref00d_rsa_mtxid, 1);
	if(res_mtx < 0)
		res = res_mtx;

	return res;
}

int ref00d_rsa_engine_initialization(void){

	int res;

	res = ksceKernelCreateMutex("Ref00dRsaMutex", 0, 0, NULL);
	if(res < 0)
		return res;

	ref00d_rsa_mtxid = res;

	res = ksceKernelCreateSema("Ref00dRsaSema", 0, 1, 1, NULL);
	if(res < 0)
		goto del_mutex;

	ref00d_rsa_semaid = res;

	res = ksceKernelCreateEventFlag("Ref00dRsaComm", 0, 0, NULL);
	if(res < 0)
		goto del_sema;

	ref00d_rsa_comm_evfid = res;

	res = ksceKernelCreateThread("Ref00dRsaEngine", ref00dRsaEngine, 0x5E, 0x2000, 0, 0xF, NULL);
	if(res < 0)
		goto del_evf;

	ref00d_rsa_thid = res;

	res = ksceKernelStartThread(ref00d_rsa_thid, 0, NULL);
	if(res < 0)
		goto del_thread;

end:
	return res;

del_thread:
	ksceKernelDeleteThread(ref00d_rsa_thid);
	ref00d_rsa_thid = -1;

del_evf:
	ksceKernelDeleteEventFlag(ref00d_rsa_comm_evfid);
	ref00d_rsa_comm_evfid = -1;

del_sema:
	ksceKernelDeleteSema(ref00d_rsa_semaid);
	ref00d_rsa_comm_evfid = -1;

del_mutex:
	ksceKernelDeleteMutex(ref00d_rsa_mtxid);
	ref00d_rsa_mtxid = -1;

	goto end;
}
