cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(ref00d)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -nostdlib")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

add_executable(ref00d
  src/main.c
)

target_link_libraries(ref00d
  taihenForKernel_stub
  taihenModuleUtils_stub
  SceIofilemgrForDriver_stub
  SceKernelUtilsForDriver_stub
  SceSysclibForDriver_stub
  SceSysmemForDriver_stub
  SceDebugForDriver_stub
  SceNpDrmForDriver_stub
  SceRegMgrForDriver_stub
)

vita_create_self(ref00d.skprx ref00d
  CONFIG exports.yml
  UNSAFE
)