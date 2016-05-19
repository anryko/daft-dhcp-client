TARGET=daft-dhcp-client
CFLAGS="-D_BSD_SOURCE"

all: $(TARGET)

clean:
	rm -f daft-dhcp-client
