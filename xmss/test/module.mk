$(TEST_DIR)/%.o: CFLAGS = $(CFLAGS_COMMON) -I$(LIB_DIR)
TEST_LDFLAGS = -L$(LIB_DIR) -lxmss -lm -lssl -lcrypto
TEST_OBJ = $(TEST_DIR)/xmss_test.o

BIN += $(TEST) $(TEST_OBJ)

$(TEST): $(TEST_OBJ) $(LIB)
	$(LD) $(TEST_OBJ) -o $(TEST) $(TEST_LDFLAGS)

