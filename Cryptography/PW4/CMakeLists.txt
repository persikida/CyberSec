cmake_minimum_required(VERSION 3.10)
project(MagmaCipher)

set(CMAKE_CXX_STANDARD 17)

add_library(magma_cipher
    magma_cipher.cpp
)

target_include_directories(magma_cipher PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(magma_main main.cpp)
target_link_libraries(magma_main PRIVATE magma_cipher)

# Optionally, include tests
enable_testing()
add_executable(test_magma test_magma.cpp)
target_link_libraries(test_magma PRIVATE magma_cipher)
add_test(NAME TestMagmaCipher COMMAND test_magma)
