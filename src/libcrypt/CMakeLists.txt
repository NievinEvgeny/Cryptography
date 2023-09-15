set(target_name libcrypt)

add_library(${target_name} STATIC
    utils.cpp
    ${PROJECT_SOURCE_DIR}/include/libcrypt/utils.hpp
)

include(CompileOptions)
set_compile_options(${target_name})

target_include_directories(
    ${target_name}
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include/
)