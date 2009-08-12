APXS_BIN     = ~/sandbox/bin/apxs
GLIB_INCLUDES = `pkg-config  --cflags glib-2.0`
GLIB_LIBS     = `pkg-config  --libs glib-2.0`
CFLAGS   = -O3 -Wall -ggdb -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
	
all: thrashd master_thrasher 

thrashd: thrashd.c 
	gcc $(CFLAGS) $(GLIB_INCLUDES) thrashd.c -o thrashd $(GLIB_LIBS) -levent

mod_thrasher: mod_thrasher.c
	$(APXS_BIN) -c mod_thrasher.c 
	$(APXS_BIN) -i -a -n thrasher mod_thrasher.la

clean:
	rm -rf thrashd *.o *.la *.slo *.lo .libs/ master_thrasher 
	
