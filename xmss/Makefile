CC := gcc
LD := gcc
CFLAGS_COMMON := -std=c99 -Wall -Wextra -Wpedantic -pedantic-errors -g -gdwarf-2

LIB_DIR := .
TEST_DIR := test

LIB := libxmss.a
TEST := $(TEST_DIR)/xmss_test
TEST_OBJ := $(TEST_DIR)/xmss_test.o
CFLAGS := $(CFLAGS_COMMON)
OBJ := hash_draft.o hfas_draft.o KeccakP-1600-reference.o KeccakSponge.o prf_draft.o SimpleFIPS202.o wots_draft.o xmss_draft.o xmssmt_draft.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

all: $(LIB) $(TEST)

$(LIB): $(OBJ)
	ar rc $(LIB) $(OBJ)

.PHONY: clean
clean:
	rm -rf $(LIB) $(OBJ) $(TEST) $(TEST_OBJ)

include $(TEST_DIR)/module.mk
