CC = clang
INCPATHS = -I/usr/local/include
CFLAGS = -g -Wall -O0 $(INCPATHS) -march=native -DDEBUG
LDLIBS = -lgmp -lssl -lcrypto
LDPATH = -L/usr/local/lib

BUILD = build
TESTS = tests

SRC = crypto.c ore.c ore_blk.c
TESTPROGS = test_ore time_ore test_ore_blk time_ore_blk

OBJPATHS = $(patsubst %.c,$(BUILD)/%.o, $(SRC))
TESTPATHS = $(addprefix $(TESTS)/, $(TESTPROGS))

all: $(OBJPATHS) $(TESTPATHS)

obj: $(OBJPATHS)

$(BUILD):
	mkdir -p $(BUILD)

$(TESTS):
	mkdir -p $(TESTS)

$(BUILD)/%.o: %.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ -c $<

$(TESTS)/%: %.c $(OBJPATHS) $(TESTS)
	$(CC) $(CFLAGS) -o $@ $< $(LDPATH) $(OBJPATHS) $(LDLIBS)

client: client.c $(OBJPATHS)
	$(CC) $(CFLAGS) -o client $< $(LDPATH) $(OBJPATHS) $(LDLIBS)

server: server.c $(OBJPATHS)
	$(CC) $(CFLAGS) -o server $< $(LDPATH) $(OBJPATHS) $(LDLIBS)

leak: leak.c $(OBJPATHS)
	$(CC) $(CFLAGS) -o leak $< $(LDPATH) $(OBJPATHS) $(LDLIBS)

clean:
	rm -rf $(BUILD) $(TESTS) *~
