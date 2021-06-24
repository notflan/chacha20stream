#!/bin/bash

gcc test.c -Iinclude -Wall --std=gnu11 -pedantic -Wextra -Og -g -o test-ffi -l:target/debug/libchacha20stream.a -lssl -lcrypto -lpthread -ldl || exit
valgrind ./test-ffi test-ffi-output
hexview test-ffi-output
rm -f test-ffi{,-output}
