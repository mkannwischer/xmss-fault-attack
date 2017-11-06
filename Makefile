CC := gcc
LD := gcc
CFLAGS_COMMON := -std=c99 -Wall -g -gdwarf-2 -O3
attack1 := attack1
attack2 := attack2
LIB_DIR := xmss
LIB := $(LIB_DIR)/libxmss.a
CFLAGS := $(CFLAGS_COMMON) -I$(LIB_DIR)
LDFLAGS := -L$(LIB_DIR) -lxmss -lm -lssl -lcrypto
OBJ := helper.o recover_wots_pk.o forge_xmssmt_signature.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

all: clean $(attack1) $(attack2) 

$(LIB):
	cd $(LIB_DIR); make

$(attack1): $(OBJ) attack.o $(LIB)
	$(LD) $(OBJ) attack.o -o $(attack1) $(LDFLAGS)

$(attack2): $(OBJ) attack2.o $(LIB)
	$(LD) $(OBJ) attack2.o -o $(attack2) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(LIB)
	rm -rf $(attack1) $(attack2) $(OBJ)
