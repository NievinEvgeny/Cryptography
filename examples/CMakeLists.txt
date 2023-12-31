set(target_name examples)

add_library(${target_name} STATIC
    signatures/sign_example.cpp
    signatures/sign_example.hpp
    ciphers/ciphers_example.cpp
    ciphers/ciphers_example.hpp
    params/gen_params.cpp
    params/gen_params.hpp
    poker/poker_example.cpp
    poker/poker_example.hpp
    blind_sign/blind_sign_example.cpp
    blind_sign/blind_sign_example.hpp
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
    ${PROJECT_SOURCE_DIR}/examples/
)