CC = gcc
CFLAGS = -Wall -g -I./include
SRC = src/*.c
OBJ = $(SRC:.c=.o)
TARGET = net_analysis

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(TARGET) $(TARGET).exe