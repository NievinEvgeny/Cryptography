set(target_name tests)

add_executable(
    ${target_name}
    utils.cpp
    ciphers.cpp
)

target_link_libraries(
    ${target_name}
    PRIVATE
    libcrypt
    examples
    GTest::gtest_main
)

target_include_directories(
    ${target_name}
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include/
    ${PROJECT_SOURCE_DIR}/external/
)

include(GoogleTest)
gtest_discover_tests(${target_name})