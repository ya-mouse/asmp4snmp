OBJ = network.o session.o asmp.o

CFLAGS = -Wall -g
LIBS   = -lssl

%.o: %.c
	$(CC) -c $(CFLAGS) $<

all: asmp

asmp: $(OBJ)
	$(CC) -o $@ $^ $(LIBS) -g

clean:
	@rm -f asmp $(OBJ)
