APXS_BIN     = ~/sandbox/bin/apxs
GLIB_INCLUDES = `pkg-config  --cflags glib-2.0`
GLIB_LIBS     = `pkg-config  --libs glib-2.0`
#CFLAGS   = -DDEBUG -Wall -ggdb -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
CFLAGS   = -DDEBUG -Wall -ggdb -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

all: thrashd libthrasher master_thrasher  

thrashd: iov.c iov.o thrashd.c 
	gcc $(CFLAGS) $(GLIB_INCLUDES) thrashd.c -o thrashd iov.o $(GLIB_LIBS) -levent

libthrasher: iov.c iov.o libthrasher.c 
	gcc $(CFLAGS) $(GLIB_INCLUDES) libthrasher.c -o libthrasher iov.o $(GLIB_LIBS) -levent

mod_thrasher: mod_thrasher.c
	$(APXS_BIN) -c mod_thrasher.c 
	$(APXS_BIN) -i -a -n thrasher mod_thrasher.la

clean:
	rm -rf thrashd *.o *.la *.slo *.lo .libs/ master_thrasher libthrasher 
	
