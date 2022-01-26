#!/bin/bash
export RUSTFLAGS="-C target-cpu=native -g"
export FFI_BUILD_FROM_SOURCE=1
export FFI_USE_CUDA=1
make 2k
make lotus-bench