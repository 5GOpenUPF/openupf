# Maybe a lower version will do
cmake_minimum_required(VERSION 3.19)

# Close the installation log
set(CMAKE_INSTALL_MESSAGE NEVER)

if(NOT PROGRAM_NAME)
  message (FATAL_ERROR "Program name not set.")
endif()

if(NOT UNIX)
    message (FATAL_ERROR "The platform only supports UNIX.")
endif()

set(PROJECT_VERSION_MAJOR 0)
set(PROJECT_VERSION_MINOR 1)
set(PROJECT_VERSION_PATCH 0)
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

# Set project name
project(upf VERSION ${PROJECT_VERSION} LANGUAGES C)

# Set global absolute path
SET(UPF_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})
SET(UPF_BUILD_PATH ${UPF_ROOT_PATH}/build)
SET(UPF_INSTALL_PATH ${UPF_ROOT_PATH}/install)
SET(UPF_CORE_PATH ${UPF_ROOT_PATH}/core)
SET(UPF_CONFIG_PATH ${UPF_ROOT_PATH}/config)
SET(UPF_LIBS_PATH ${UPF_ROOT_PATH}/libs)
SET(UPF_TEST_PATH ${UPF_ROOT_PATH}/test)
SET(UPF_RESTFUL_PKGCFG_PATH ${UPF_INSTALL_PATH}/lib/pkgconfig)
SET(UPF_DPDK_PKGCFG_PATH ${UPF_BUILD_PATH}/dpdk/install/lib/pkgconfig)

# Compile files
SET(UPF_HEADER_FILES "")
SET(UPF_SOURCE_FILES "")
FILE(GLOB_RECURSE UPF_HEADER_FILES ${UPF_CORE_PATH}/include/*.h)

if(EXISTS "${UPF_CORE_PATH}/service/pfcp/upc_high_availability.c" AND EXISTS "${UPF_CORE_PATH}/service/loadbalancer/lb_ha_mgmt.c")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLED_HA")
    message(STATUS "Enabled High Availability")
endif()

set(CMAKE_MODULE_PATH "${UPF_LIBS_PATH};${CMAKE_MODULE_PATH}")
if(${PROGRAM_NAME} MATCHES "fpu" OR ${PROGRAM_NAME} MATCHES "lbu")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DALLOW_EXPERIMENTAL_API -DCONFIG_FP_DPDK_PORT -DENABLE_DPDK_LIB")

    set (ENV{PKG_CONFIG_PATH} "${PKG_CONFIG_PATH}:${UPF_DPDK_PKGCFG_PATH}")
    find_package(PkgConfig REQUIRED)
    pkg_search_module(PKG_DPDK REQUIRED libdpdk)
elseif(${PROGRAM_NAME} MATCHES "smu")
    set (ENV{PKG_CONFIG_PATH} "${PKG_CONFIG_PATH}:${UPF_RESTFUL_PKGCFG_PATH}")
    find_package(PkgConfig REQUIRED)
    pkg_search_module(PKG_ULFIUS REQUIRED libulfius)
    pkg_search_module(PKG_ORCANIA REQUIRED liborcania)
endif()

# Set compile flag
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
                        -D_GNU_SOURCE \
                        -DPRODUCT_IS_${PROGRAM_NAME} \
                        -Wl,-rpath,/opt/upf/lib"
)

# Set installation directory
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  message(STATUS "Setting default CMAKE_INSTALL_PREFIX path to ${UPF_INSTALL_PATH}")
  set(CMAKE_INSTALL_PREFIX "${UPF_INSTALL_PATH}" CACHE STRING "The path to use for make install" FORCE)
endif()
message(STATUS "CMAKE_INSTALL_PREFIX is ${CMAKE_INSTALL_PREFIX}")

add_definitions(-fPIC -g -O2 -pthread -march=native 
    -Wmaybe-uninitialized -Wimplicit 
    -Werror -Wall -Waddress -Wchar-subscripts 
    -Wenum-compare -Wimplicit-int -Wimplicit-function-declaration 
    -Wcomment -Wformat -Wmain -Wmissing-braces -Wnonnull
    -Wparentheses -Wpointer-sign -Wreturn-type -Wsequence-point 
    -Wno-strict-aliasing -Wstrict-overflow=1 -Wswitch -Wtrigraphs 
    -Wuninitialized -Wunknown-pragmas -Wunused-function -Wunused-label 
    -Wunused-value -Wunused-variable -Wvolatile-register-var)

macro(INCLU_SUBDIR curdir)
    file(GLOB children RELATIVE ${curdir} ${curdir}/*)
    set(dirlist "")
    foreach(child ${children})
        if(IS_DIRECTORY ${curdir}/${child})
            INCLU_SUBDIR(${curdir}/${child})
            include_directories(${curdir}/${child})
        endif()
    endforeach()
endmacro()
INCLU_SUBDIR(${UPF_CORE_PATH})

# Add sub directories
add_subdirectory(core)
if(${PROGRAM_NAME} MATCHES "stub" AND EXISTS ${UPF_TEST_PATH})
    set(TEST_EXEC_LIST "")
    add_subdirectory(test)
endif()

############################################################
# Install
############################################################

# Binaries
install (TARGETS ${PROGRAM_NAME} RUNTIME 
    DESTINATION ${UPF_INSTALL_PATH}/bin)
install (TARGETS cli RUNTIME 
    DESTINATION ${UPF_INSTALL_PATH}/bin)

# Library
# Note: may not work on windows
install (TARGETS service_${PROGRAM_NAME} LIBRARY 
    DESTINATION ${UPF_INSTALL_PATH}/lib)

# Header files
install(FILES ${UPF_HEADER_FILES}
    DESTINATION ${UPF_INSTALL_PATH}/include)

# Config
install (DIRECTORY ${UPF_CONFIG_PATH}/${PROGRAM_NAME} 
    DESTINATION ${UPF_INSTALL_PATH}/config)

# Test
if(${PROGRAM_NAME} MATCHES "stub" AND EXISTS ${UPF_TEST_PATH})
    SET(UPF_CONFIG_PATH ${UPF_ROOT_PATH}/config)
    
    # Binaries
    install (TARGETS ${TEST_EXEC_LIST} RUNTIME 
        DESTINATION ${UPF_INSTALL_PATH}/test)
    
    # Config
    install (DIRECTORY ${UPF_CONFIG_PATH}/${PROGRAM_NAME} 
        DESTINATION ${UPF_INSTALL_PATH}/config)
    
    # Test
    install (DIRECTORY ${UPF_TEST_PATH}/autotest 
        DESTINATION ${UPF_INSTALL_PATH}/test/)
endif()

