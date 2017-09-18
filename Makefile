CC := gcc
LD := gcc
CFLAGS_COMMON := -std=c99 -Wall -g -gdwarf-2 -O3
TEST := attack
LIB_DIR := xmss
LIB := $(LIB_DIR)/libxmss.a
CFLAGS := $(CFLAGS_COMMON) -I$(LIB_DIR)
LDFLAGS := -L$(LIB_DIR) -lxmss -lm -lssl -lcrypto
OBJ := helper.o recover_wots_pk.o forge_xmssmt_signature.o attack.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

all: clean $(TEST)

$(LIB):
	cd $(LIB_DIR); make

$(TEST): $(OBJ) $(LIB)
	$(LD) $(OBJ) -o $(TEST) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(LIB)
	rm -rf $(TEST) $(OBJ)
