.PHONY: all clean

# MinGW cross-compiler (Linux → Windows PE) — install: apt install mingw-w64
CC     = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -O2 -masm=intel -mconsole
TARGET = example_injection.exe
SRCS   = example_injection.c SW4_mingwSyscalls.c SW4_mingwSyscalls_stubs.c
RM     = rm -f

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	$(RM) $(TARGET)
