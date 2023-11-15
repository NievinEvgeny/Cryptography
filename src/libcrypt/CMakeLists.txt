set(target_name libcrypt)

add_library(${target_name} STATIC
    utils.cpp
    ${PROJECT_SOURCE_DIR}/include/libcrypt/utils.hpp
    ciphers.cpp
    ${PROJECT_SOURCE_DIR}/include/libcrypt/ciphers.hpp
    signatures.cpp
    ${PROJECT_SOURCE_DIR}/include/libcrypt/signatures.hpp
    poker.cpp
    ${PROJECT_SOURCE_DIR}/include/libcrypt/poker.hpp
    blind_sign.cpp
    ${PROJECT_SOURCE_DIR}/include/libcrypt/blind_sign.hpp
)

include(CompileOptions)
set_compile_options(${target_name})

target_include_directories(
    ${target_name}
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include/
    ${PROJECT_SOURCE_DIR}/external/
)