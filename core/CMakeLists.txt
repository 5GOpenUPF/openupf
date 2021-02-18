# Set project name
project(upf-${PROGRAM_NAME} VERSION ${PROJECT_VERSION} LANGUAGES C)

# Add sub directories
add_subdirectory(util)
add_subdirectory(platform)
add_subdirectory(service)

# Append header files
SET(UPF_HEADER_FILES ${UPF_HEADER_FILES} PARENT_SCOPE)

############################################################
# Create an executable
############################################################
add_executable(${PROGRAM_NAME} ${UPF_CORE_PATH}/main.c)

target_link_libraries(${PROGRAM_NAME} 
    PUBLIC
        pthread
        edit
        tinfo
        m
)

# dpdk static library needs (-Wl,--whole-archive)
set(EXTRA_C_LIBS -Wl,--whole-archive 
    service_${PROGRAM_NAME}
)

if(${PROGRAM_NAME} MATCHES "smu")
    target_link_directories(${PROGRAM_NAME} 
        PRIVATE 
            ${UPF_INSTALL_PATH}/lib
    )
    
    target_link_libraries(${PROGRAM_NAME} 
        PRIVATE 
            ulfius 
            orcania
    )
elseif(${PROGRAM_NAME} MATCHES "fpu" OR ${PROGRAM_NAME} MATCHES "lbu")
    if(${DPDK_COMPILE_MODE} MATCHES "make")
        add_dependencies(${PROGRAM_NAME} LIBDPDK-build)
        
        #target_link_directories(${PROGRAM_NAME} 
        #    PRIVATE
        #        ${LIBDPDK_LIBS_DIR}
        #)
        
        target_link_libraries(${PROGRAM_NAME}
            PRIVATE 
                c 
                dl 
                numa
                ${LIBDPDK_LIBS}
        )
        
        set(EXTRA_C_LIBS ${EXTRA_C_LIBS} 
            dpdk
        )
    elseif(${DPDK_COMPILE_MODE} MATCHES "ninja")
        target_link_directories(${PROGRAM_NAME} 
            PRIVATE
                ${PKG_DPDK_LIBRARY_DIRS}
        )
        
        target_link_libraries(${PROGRAM_NAME}
            PRIVATE 
                ${PKG_DPDK_LIBRARIES}
        )
        
        target_compile_options(${PROGRAM_NAME} 
            PRIVATE 
                -Wl,-rpath=/opt/upf/dpdk/lib64
        )
    else()
        target_link_directories(${PROGRAM_NAME} 
            PRIVATE
                ${LIBDPDK_LIBS_DIR}
        )
        
        target_link_libraries(${PROGRAM_NAME}
            PRIVATE 
                c 
                dl 
                numa
        )
        
        set(EXTRA_C_LIBS ${EXTRA_C_LIBS} 
            dpdk
        )
    endif()
endif()

set(EXTRA_C_LIBS ${EXTRA_C_LIBS} 
    -Wl,--no-whole-archive
)

target_link_libraries(${PROGRAM_NAME} PRIVATE ${EXTRA_C_LIBS})
