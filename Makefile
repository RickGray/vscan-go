TARGETS := vscan-go

all: $(TARGETS)

vscan-go: *.go
	      go build

.PHONY: clean install uninstall vscan-go

install: $(TARGETS)
	install -m 755 $(TARGETS) /usr/local/bin

uninstall:
	rm -f $(addprefix /usr/local/bin/, $(TARGETS))

clean:
	go clean