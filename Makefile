OBJ = session.o asmpASMPDomain.o asmpAIDPDomain.o
OBJH = $(OBJ) snmphook.o

CFLAGS = -Wall -g -fPIC -DPIC
LIBS   = -lssl -lsnmp

%.o: %.c
	$(CC) -c $(CFLAGS) $<

all: asmp libsnmphook.so

asmp: asmp.o network.o $(OBJ)
	$(CC) -o $@ $^ $(LIBS) -g

libsnmphook.so: $(OBJH)
	$(CC) -o $@ $^ -shared -Wl,-soname,libsnmphook.so -fPIC -ldl $(LIBS)

test: libsnmphook.so
	LD_PRELOAD=$(PWD)/libsnmphook.so snmpget -v1 -c public aidp:ff02::ffff  1.3.6.1 -On -d -Dtdomain -Dnetsnmp_sockaddr_in
#	LD_PRELOAD=$(PWD)/libsnmphook.so snmpget -v3 asmp:localhost  1.3.6.1 -On -d -Dtdomain -Dnetsnmp_sockaddr_in
#	LD_PRELOAD=$(PWD)/libsnmphook.so snmpget -v3 asmps:localhost 1.3.6.1 -On -d -Dtdomain -Dnetsnmp_sockaddr_in

clean:
	@rm -f asmp libasmphook.so asmp.o network.o $(OBJ) $(OBJH)
