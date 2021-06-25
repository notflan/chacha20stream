#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cc20.h>

#define TRY(expr) do { if(CC20_ERR(res = (expr))) { fprintf(stderr, "cc20 error %d: " #expr "\n", (int)res); goto fail; } } while(0)

const char write_string[] = "Hello world?";

FILE* wrap_stream(FILE* wrap, enum cc20_mode mode, const cc20_key_t* k, const cc20_iv_t* i, cc20_meta_t *restrict meta)
{
	cc20_meta_t _meta = {0};
	if(!meta) meta = &_meta;

	if(CC20_OK(cc20_gen_meta(wrap, k, i, mode, meta)))
	{	
		cc20_sink_t* sink;
		if(CC20_OK(cc20_gen_sink(meta, &sink)))
			return cc20_wrap_sink(sink, (struct cc20_wrap_cfg[1]) {{ .keep_alive = 1 }} );
		else perror("cc20_gen_sink()");
	} else perror("cc20_gen_meta()");
	exit(-1);
}

FILE* wrap_file(const char* filename, enum cc20_mode mode, cc20_meta_t* restrict meta)
{
	cc20_meta_t _meta = {0};
	if(!meta) meta = &_meta;

	FILE* wrap = fopen(filename, "w+b");
	if(!wrap) {
		perror("fopen()");
		exit(-1);
	}
	return wrap_stream(wrap, mode, NULL, NULL, meta);
/*
	if(CC20_OK(cc20_gen_meta(wrap, NULL, NULL, mode, meta))
	&& CC20_OK(cc20_gen(meta, &wrap))) return wrap;
	perror("cc20_gen()");
	exit(-1);*/
}

int main(int argc, char** argv)
{
	((void)argc);
	((void)argv);
	//if(!argv[1]) return 1;	

	cc20_meta_t meta;
	unsigned char* mems = NULL;
	size_t mems_sz =0;

	FILE* output = wrap_stream(open_memstream((char**)&mems, &mems_sz), CC20_ENCRYPT, NULL, NULL, &meta);//wrap_file(argv[1], CC20_ENCRYPT, &meta);
	size_t wsz;
	printf("written %lu bytes\n", (wsz=fwrite(write_string, 1, strlen(write_string), output)));

	fclose(output);

	FILE* input = meta.backing;
	long sz = ftell(input);

	printf(" -> backing stream tell: %ld\n", sz);
	if(sz<=0) return (perror("ftell()"), -1);
	else if(wsz != (size_t)sz) return (fprintf(stderr, "incorrect ftell(): (expected %lu, got %ld)\n", wsz, sz), -2);

	if(fseek(input, 0L, SEEK_SET)!=0) return (perror("fseek()"), -3);
	
	unsigned char encbuf[wsz];
	if(fread(encbuf, 1, wsz, input)!=wsz) return (perror("fread()"), -4);

	printf("decrypted: '"); { 
	/* owning stdout */
		output = wrap_stream(stdout, CC20_DECRYPT, (const cc20_key_t*) &meta.key, (const cc20_iv_t*) &meta.iv, NULL);
		wsz = fwrite(encbuf, 1, wsz, output);
		fclose(output);
	/* releases stdout */
	printf("'\n"); }
	printf("written %lu bytes\n", wsz);

	fclose(input);
	printf("\nbacking buffer contains: %lu bytes\n", mems_sz);
	if(mems) free(mems);

	return 0;
}
