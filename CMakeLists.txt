cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(reF00D)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O2 -fno-inline")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

enable_language(C ASM)

add_executable(reF00D
  src/main.c
  src/ref00d_utils.c
  src/ref00d_kprx_auth.c
  src/ref00d_aes_cbc.S
  src/ref00d_rsa_engine.c
)

target_link_libraries(reF00D
  SceCpuForDriver_stub
  SceDebugForDriver_stub
  ScePmMgrForDriver_stub
  SceSblAIMgrForDriver_stub
  SceSblPostSsMgrForDriver_stub
  SceSblSsMgrForDriver_stub
  SceSysclibForDriver_stub
  SceSysmemForDriver_stub
  SceSysrootForKernel_stub
  SceKernelUtilsForDriver_stub
  SceThreadmgrForDriver_stub
  SceModulemgrForDriver_stub
  taihenForKernel_stub
  taihenModuleUtils_stub
)

set_target_properties(reF00D
  PROPERTIES LINK_FLAGS "-nostdlib"
  COMPILE_FLAGS "-D__PSP2_KERNEL__ -D__PSP2FILE__='\"$(subst ${CMAKE_SOURCE_DIR}/src/,,$(abspath $<))\"' -D__PSP2FILEHASH__='0x$(shell echo -n \"$(subst ${CMAKE_SOURCE_DIR}/src/,,$(abspath $<))\" | shasum -a 1 | cut -c 1-8)'"
)

vita_create_self(reF00D.skprx reF00D
  CONFIG exports.yml
  UNSAFE
  STRIPPED
  REL_OPTIMIZE
)

vita_create_stubs(stubs reF00D ${CMAKE_SOURCE_DIR}/exports.yml KERNEL)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/ref00d_kprx_auth.h DESTINATION "$ENV{VITASDK}/arm-vita-eabi/include")
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/build/stubs/libReAuthMgr_stub.a DESTINATION "$ENV{VITASDK}/arm-vita-eabi/lib")
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/build/stubs/libReAuthMgrForDebugger_stub.a DESTINATION "$ENV{VITASDK}/arm-vita-eabi/lib")
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/build/stubs/libReAuthMgrForKernel_stub.a DESTINATION "$ENV{VITASDK}/arm-vita-eabi/lib")
