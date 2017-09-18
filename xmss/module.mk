$(LIB_DIR)/%.o: CFLAGS = $(CFLAGS_COMMON)
LIB_OBJ = $(LIB_DIR)/hash_draft.o $(LIB_DIR)/hfas_draft.o $(LIB_DIR)/KeccakP-1600-reference.o $(LIB_DIR)/KeccakSponge.o $(LIB_DIR)/prf_draft.o $(LIB_DIR)/SimpleFIPS202.o $(LIB_DIR)/wots_draft.o $(LIB_DIR)/xmss_draft.o $(LIB_DIR)/xmssmt_draft.o

$(LIB): $(LIB_OBJ)
	ar rc $(LIB) $(LIB_OBJ)

BIN += $(LIB_OBJ) $(LIB)

