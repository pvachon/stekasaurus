OBJ = stek_server.o \
	  stek_common.o

DEFINES = -D_GNU_SOURCE
CFLAGS = -O0 -ggdb
INCLUDES = -I.
LINK = -lssl -lcrypto

.c.o:
	$(CC) $(INCLUDES) $(DEFINES) -c $<

stek_server: $(OBJ)
	$(CC) stek_common.o stek_server.o $(LINK) -o stek_server

stek_client: $(OBJ)
	$(CC) stek_client.o $(LINK) -o stek_client

all: stek_server

clean:
	$(RM) $(OBJ)
	$(RM) stek_server.o stek_server

.PHONY: all clean stek_server stek_client
