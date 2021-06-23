#!/bin/bash

gcc test.c -Iinclude -Wall --std=gnu11 -pedantic -Wextra -O3 -o test-ffi -l:target/release/libchacha20stream.so || exit
#-lssl -lcrypto -lpthread -ldl || exit
valgrind ./test-ffi test-ffi-output
hexview test-ffi-output
rm -f test-ffi{,-output}
