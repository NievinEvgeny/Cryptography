set(target_name examples)

add_library(${target_name} STATIC
    ciphers/cipher_examples.cpp
    ciphers/cipher_examples.hpp
)

include(CompileOptions)
set_compile_options(${target_name})

target_link_libraries(
    ${target_name}
    PRIVATE
    libcrypt
    cxxopts
)

target_include_directories(
    ${target_name}
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include/
)