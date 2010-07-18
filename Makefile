OBJ = network.o session.o asmp.o
OBJH = asmpASMPDomain.o asmpAIDPDomain.o session.o snmphook.o

CFLAGS = -Wall -g
LIBS   = -lssl -lsnmp

%.o: %.c
	$(CC) -c $(CFLAGS) $<

all: asmp libsnmphook.so

asmp: $(OBJ)
	$(CC) -o $@ $^ $(LIBS) -g

libsnmphook.so: $(OBJH)
	$(CC) -o $@ $^ -shared -Wl,-soname,libsnmphook.so -ldl -lsnmp

test: libsnmphook.so
	LD_PRELOAD=$(PWD)/libsnmphook.so snmpget -v3 aidp:localhost  1.3.6.1 -On -d -Dtdomain -Dnetsnmp_sockaddr_in
	LD_PRELOAD=$(PWD)/libsnmphook.so snmpget -v3 asmp:localhost  1.3.6.1 -On -d -Dtdomain -Dnetsnmp_sockaddr_in
	LD_PRELOAD=$(PWD)/libsnmphook.so snmpget -v3 asmps:localhost 1.3.6.1 -On -d -Dtdomain -Dnetsnmp_sockaddr_in

clean:
	@rm -f asmp libasmphook.so asmphook.o $(OBJ)
