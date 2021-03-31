
# Add sub directories
add_subdirectory(cli)
add_subdirectory(log)
add_subdirectory(ros)
add_subdirectory(buffer)
add_subdirectory(trans)

# Append source files
SET(UPF_SOURCE_FILES ${UPF_SOURCE_FILES} PARENT_SCOPE)

# Append header files
FILE(GLOB header_files ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h)
LIST(APPEND UPF_HEADER_FILES ${header_files})
SET(UPF_HEADER_FILES ${UPF_HEADER_FILES} PARENT_SCOPE)
