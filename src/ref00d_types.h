/*
 * reF00D
 * Copyright (C) 2021, FAPS TEAM
 */

#ifndef _PSP2_REF00D_TYPE_H_
#define _PSP2_REF00D_TYPE_H_

#define REF00D_DEBUG 0

#if defined(REF00D_DEBUG) && (REF00D_DEBUG == 1)
  #define printf ksceDebugPrintf
#else
  #define printf(...)
#endif

#endif /* _PSP2_REF00D_TYPE_H_ */
