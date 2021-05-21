
if(${PROGRAM_NAME} MATCHES "fpu" OR ${PROGRAM_NAME} MATCHES "lbu")
    add_subdirectory(dpdk)
endif()

# Append source files
FILE(GLOB source_files *.c)
LIST(APPEND UPF_SOURCE_FILES ${source_files})
SET(UPF_SOURCE_FILES ${UPF_SOURCE_FILES} PARENT_SCOPE)

# Append header files
FILE(GLOB header_files *.h)
LIST(APPEND UPF_HEADER_FILES ${header_files})
SET(UPF_HEADER_FILES ${UPF_HEADER_FILES} PARENT_SCOPE)
