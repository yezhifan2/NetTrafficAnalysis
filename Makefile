# 编译器和选项
CC = gcc
CFLAGS = -Wall -I include

# 目标文件 (和你的 ReadMe 保持一致，放在 build 目录下)
TARGET = build/main.exe

# 获取 src 目录下所有的 .c 文件 (这是 Makefile 的正确写法)
SRCS = $(wildcard src/*.c)

# 默认执行的目标
all: $(TARGET)

# 编译规则 (一键编译所有 .c 文件，和你手敲的命令效果完全一样)
$(TARGET): $(SRCS)
	$(CC) $(SRCS) $(CFLAGS) -o $(TARGET)

# 清理命令 (清除生成的 exe)
clean:
	rm -f $(TARGET)