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
set(EXTRA_C_LIBS 
    service_${PROGRAM_NAME}
)

target_link_libraries(${PROGRAM_NAME} PRIVATE ${EXTRA_C_LIBS})
