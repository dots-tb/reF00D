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

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -Os -fno-inline")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

enable_language(C ASM)

add_executable(reF00D
  src/main.c
  src/ref00d_utils.c
  src/ref00d_kprx_auth.c
  src/ref00d_kprx_auth_keys_release.c
  src/ref00d_aes_cbc.S
  src/ref00d_rsa_engine.c
)

target_link_libraries(reF00D
  SceCpuForDriver_stub
  SceDebugForDriver_stub
  ScePmMgrForDriver_stub
  SceSblAIMgrForDriver_stub
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
  COMPILE_FLAGS "-D__VITA_KERNEL__"
)

vita_create_self(reF00D.skprx reF00D
  CONFIG exports.yml
  UNSAFE
  STRIPPED
)

vita_create_stubs(stubs reF00D ${CMAKE_SOURCE_DIR}/exports.yml KERNEL)
