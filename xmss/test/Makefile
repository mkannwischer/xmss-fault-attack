CC := gcc
LD := gcc
CFLAGS_COMMON := -std=c99 -Wall -g -gdwarf-2 -O3
TEST := xmss_test
LIB_DIR := ..
LIB := $(LIB_DIR)/libxmss.a
CFLAGS := $(CFLAGS_COMMON) -I$(LIB_DIR)
LDFLAGS := -L$(LIB_DIR) -lxmss -lm -lssl -lcrypto
OBJ := xmss_test.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

all: $(TEST)

$(LIB):
	cd $(LIB_DIR); make

$(TEST): $(OBJ) $(LIB)
	$(LD) $(OBJ) -o $(TEST) $(LDFLAGS)

.PHONY: clean
clean:
	rm -rf $(TEST) $(OBJ)

