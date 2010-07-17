OBJ = network.o session.o asmp.o

CFLAGS = -Wall -g
LIBS   = -lssl -lsnmp

%.o: %.c
	$(CC) -c $(CFLAGS) $<

all: asmp libsnmphook.so

asmp: $(OBJ)
	$(CC) -o $@ $^ $(LIBS) -g

libsnmphook.so: snmphook.o
	$(CC) -o $@ $^ -shared -Wl,-soname,libsnmphook.so -ldl -lsnmp

test: libsnmphook.so
	LD_PRELOAD=$PWD/libsnmphook.so snmpget -v 1 -c public localhost 1.3.6.1 -On -d

clean:
	@rm -f asmp libasmphook.so asmphook.o $(OBJ)
