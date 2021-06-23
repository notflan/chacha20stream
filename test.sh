#!/bin/bash

gcc test.c -Iinclude -Wall --std=gnu11 -pedantic -Wextra -O3 -o test-ffi -l:target/debug/libchacha20stream.so || exit
./test-ffi
rm -f test-ffi
