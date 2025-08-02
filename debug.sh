#!/bin/bash

# Build the project
make clean && make

# Start QEMU in debug mode in background
make debug &
QEMU_PID=$!

# Wait a moment for QEMU to start
sleep 2

# Start GDB
gdb -x debug.gdb

# Kill QEMU when GDB exits
kill $QEMU_PID 