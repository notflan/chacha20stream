#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cc20.h>

#define IGNORE(v) ((void)(v))

static ssize_t cc20c_read(void* cookie, char* buffer, size_t size)
{
	IGNORE(cookie);
	IGNORE(buffer);
	IGNORE(size);

	return -1;
}

static ssize_t cc20c_write(void* cookie, const char* buffer, size_t size)
{
	register int c = cc20_write(buffer, 1, size, cookie);
	return c < 0 ? 0 : c;
}

static int cc20c_seek(void* cookie, off64_t* pos, int w)
{
	IGNORE(cookie);
	IGNORE(pos);
	IGNORE(w);

	return -1;
}

static int cc20c_close(void* cookie)
{
	struct cc20_metadata meta ={0};
	cc20_close_sink(cookie, &meta);
	if(meta.backing) fclose(meta.backing);
	else return -1;
	return 0;
}

FILE* _cc20c_create(cc20_sink_t* restrict sink)
{
	return fopencookie(sink, "wb", (cookie_io_functions_t){
		.read =		&cc20c_read,
		.write =	&cc20c_write,
		.seek =		&cc20c_seek,
		.close =	&cc20c_close,
	});
}
