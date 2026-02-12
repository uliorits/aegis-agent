CC ?= gcc
PREFIX ?= /usr/local
DESTDIR ?=

BIN := aegis-agent
BINDIR := $(PREFIX)/bin
ETCDIR := $(PREFIX)/etc
CONF_FILE := aegis-agent.conf

SRCS := $(wildcard core/*.c telemetry/*.c baseline/*.c anomaly/*.c classifier/*.c comms/*.c)
OBJS := $(SRCS:.c=.o)
DEPS := $(OBJS:.o=.d)

CPPFLAGS ?=
CPPFLAGS += -I.

CFLAGS ?= -O2
CFLAGS += -std=c11 -Wall -Wextra -MMD -MP

LDFLAGS ?=
LDLIBS ?= -lm -pthread

.PHONY: all clean install uninstall run

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	@if [ -f "$(CONF_FILE)" ]; then \
		install -d $(DESTDIR)$(ETCDIR); \
		install -m 0644 "$(CONF_FILE)" "$(DESTDIR)$(ETCDIR)/$(CONF_FILE)"; \
	fi

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(BIN)"
	rm -f "$(DESTDIR)$(ETCDIR)/$(CONF_FILE)"

run: $(BIN)
	./$(BIN)

clean:
	rm -f $(BIN) $(OBJS) $(DEPS)

-include $(DEPS)
