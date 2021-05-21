# Set the project name
project(service_${PROGRAM_NAME})

#get_property(dirs DIRECTORY ${CMAKE_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)
#message("include_directories is ${dirs}")

# Add sub directories
add_subdirectory(common)

if(${PROGRAM_NAME} MATCHES "fpu")
    add_subdirectory(fastpass)
elseif(${PROGRAM_NAME} MATCHES "lbu")
    add_subdirectory(loadbalancer)
elseif(${PROGRAM_NAME} MATCHES "smu")
    add_subdirectory(pfcp)
elseif(${PROGRAM_NAME} MATCHES "stub" AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/stub)
    add_subdirectory(stub)
endif()

# Append header files
LIST(APPEND UPF_HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/service.h)
SET(UPF_HEADER_FILES ${UPF_HEADER_FILES} PARENT_SCOPE)

# Add a library with the above sources
add_library(${PROJECT_NAME} STATIC ${CMAKE_CURRENT_SOURCE_DIR}/service.c ${UPF_SOURCE_FILES})

if(${PROGRAM_NAME} MATCHES "smu")
    target_compile_options(${PROJECT_NAME} 
        PRIVATE
            ${PKG_ULFIUS_CFLAGS}
            ${PKG_ORCANIA_CFLAGS}
    )
    
    target_link_directories(${PROJECT_NAME} 
        PRIVATE 
            ${UPF_INSTALL_PATH}/lib
    )
    
    target_link_libraries(${PROJECT_NAME}
        PRIVATE 
            #${PKG_ULFIUS_LDFLAGS}
            #${PKG_ULFIUS_LIBRARIES}
            ulfius
            ${PKG_ORCANIA_LDFLAGS}
            ${PKG_ORCANIA_LIBRARIES}
    )
    
elseif(${PROGRAM_NAME} MATCHES "fpu" OR ${PROGRAM_NAME} MATCHES "lbu")
    target_compile_definitions(${PROJECT_NAME} 
        PRIVATE 
            RTE_MACHINE_CPUFLAG_SSE
            RTE_MACHINE_CPUFLAG_SSE2
            RTE_MACHINE_CPUFLAG_SSE3
            RTE_MACHINE_CPUFLAG_SSSE3
            RTE_MACHINE_CPUFLAG_SSE4_1
            RTE_MACHINE_CPUFLAG_SSE4_2
            RTE_MACHINE_CPUFLAG_AES
            RTE_MACHINE_CPUFLAG_PCLMULQDQ
            RTE_MACHINE_CPUFLAG_AVX
    )
    
    target_compile_options(${PROJECT_NAME} 
        PRIVATE
            ${PKG_DPDK_CFLAGS}
    )
    target_link_libraries(${PROJECT_NAME}
        PRIVATE 
            ${PKG_DPDK_LDFLAGS}
            #${PKG_DPDK_STATIC_LIBRARIES}
            ${PKG_DPDK_LIBRARIES}
    )
endif()
