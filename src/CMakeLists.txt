add_compile_definitions(_POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700)
add_definitions(-D_BSD_SOURCE)

if(APPLE)
    add_definitions(-D_DARWIN_C_SOURCE)
endif()

find_program(LINT "clang-tidy")
IF (LINT)
    set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*,-llvmlibc-restrict-system-libc-headers,-cppcoreguidelines-init-variables,-clang-analyzer-security.insecureAPI.strcpy,-concurrency-mt-unsafe,-android-cloexec-accept,-android-cloexec-dup,-google-readability-todo,-cppcoreguidelines-avoid-magic-numbers,-readability-magic-numbers,-cert-dcl03-c,-hicpp-static-assert,-misc-static-assert,-altera-struct-pack-align,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling;--quiet")
ENDIF ()

include(FindPCAP.cmake)

# Make an executable
add_executable(SPOOF ${COMMON_SOURCE_LIST} ${SPOOF_SOURCE_LIST} ${HEADER_LIST})

# We need this directory, and users of our library will need it too
target_include_directories(SPOOF PRIVATE ../include)
target_include_directories(SPOOF PRIVATE /usr/include)
target_include_directories(SPOOF PRIVATE /usr/local/include)
target_link_directories(SPOOF PRIVATE /usr/lib)
target_link_directories(SPOOF PRIVATE /usr/local/lib)


# All users of this library will need at least C17
target_compile_features(SPOOF PUBLIC c_std_17)
target_compile_options(SPOOF PRIVATE -g)
target_compile_options(SPOOF PRIVATE -fstack-protector-all -ftrapv)
target_compile_options(SPOOF PRIVATE -Wpedantic -Wall -Wextra)
target_compile_options(SPOOF PRIVATE -Wdouble-promotion -Wformat-nonliteral -Wformat-security -Wformat-y2k -Wnull-dereference -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-local-typedefs -Wstrict-overflow=5 -Wmissing-noreturn -Walloca -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wpointer-arith -Wabsolute-value -Wundef -Wexpansion-to-defined -Wunused-macros -Wno-endif-labels -Wbad-function-cast -Wcast-qual -Wwrite-strings -Wconversion -Wdangling-else -Wdate-time -Wempty-body -Wsign-conversion -Wfloat-conversion -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wpacked -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wlong-long -Wvariadic-macros -Wdisabled-optimization -Wstack-protector -Woverlength-strings)

find_library(LIBM m REQUIRED)
find_library(LIBSOCKET socket)

target_link_libraries(SPOOF PRIVATE ${LIBM})
target_link_libraries(SPOOF PRIVATE ${PCAP_LIBRARY})
set_target_properties(SPOOF PROPERTIES OUTPUT_NAME "spoof")


install(TARGETS SPOOF DESTINATION bin)


# IDEs should put the headers in a nice place
source_group(
        TREE "${PROJECT_SOURCE_DIR}/include"
        PREFIX "Header Files"
        FILES ${HEADER_LIST}
)

add_custom_target(
        format
        COMMAND clang-format
        -i
        ${HEADER_LIST}
        ${COMMON_SOURCE_LIST}
        ${SPOOF_SOURCE_LIST}
)
