# GDB script for Solar OS debugging
target remote localhost:1234

# Set architecture
set architecture i386:x86-64

# Set target
set target-async off

# Load symbols
symbol-file build/bin/solarImg

# Break at kernel entry point
break _start
break kernel_main

# Break at Pixel function
break Pixel

# Break at page fault handler
break isr_dispatch

# Continue execution
continue 