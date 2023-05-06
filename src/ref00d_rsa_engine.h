/*
 * reF00D RSA Engine
 * Copyright (C) 2021, FAPS TEAM
 */

#ifndef _REF00D_RSA_ENGINE_H_
#define _REF00D_RSA_ENGINE_H_

int ref00dRsaEngineRequest(void *src, void *k, void *n, void *hash);

int ref00dRsaEngineWaitWork(void);

int ref00d_rsa_engine_initialization(void);

#endif	/* _REF00D_RSA_ENGINE_H_ */
