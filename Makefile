OBJ = session.o asmpASMPDomain.o asmpAIDPDomain.o
OBJH = $(OBJ) snmphook.o

CFLAGS = -Wall -g -fPIC -DPIC
LIBS   = -lssl -lsnmp

%.o: %.c
	$(CC) -c $(CFLAGS) $<

all: asmp aidp libsnmphook.so DSR-MIB.txt

%.txt: xml2mib.xslt %.xml
	xsltproc $^ > $@

asmp: asmp.o network.o $(OBJ)
	$(CC) -o $@ $^ $(LIBS) -g

aidp: aidp.o $(OBJ)
	$(CC) -o $@ $^ $(LIBS) -g

libsnmphook.so: $(OBJH)
	$(CC) -o $@ $^ -shared -Wl,-soname,libsnmphook.so -fPIC -ldl $(LIBS)

test: libsnmphook.so
#	LD_PRELOAD=$(PWD)/libsnmphook.so snmpget -v1 -c public aidp:ff02::ffff  1.3.6.1 -On -d -Dtdomain -Dnetsnmp_sockaddr_in
#	LD_PRELOAD=$(PWD)/libsnmphook.so snmpget -v3 asmp:localhost  1.3.6.1 -On -d -Dtdomain -Dnetsnmp_sockaddr_in
	LD_PRELOAD=$(PWD)/libsnmphook.so snmpget -v1 -c public asmps:192.168.1.100 1.3.6.1 -On -d -Dtdomain -Dnetsnmp_sockaddr_in

clean:
	@rm -f asmp aidp libasmphook.so asmp.o aidp.o network.o $(OBJ) $(OBJH)
