#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cc20.h>

#define TRY(expr) do { if(CC20_ERR(res = (expr))) { fprintf(stderr, "cc20 error %d: " #expr "\n", (int)res); goto fail; } } while(0)

const char write_string[] = "Hello world?";

int main(int argc, char** argv)
{
	cc20_meta_t meta;
	cc20_result_t res;

	FILE* output = argv[1] ? fopen(argv[1], "wb") : stdout;
	if(!output) { perror("failed to open output"); return -1; }

	TRY(cc20_gen_meta(output, NULL, NULL, CC20_ENCRYPT, &meta));
	TRY(cc20_gen(&meta, &output));

	printf("written %lu bytes\n", fwrite(write_string, 1, strlen(write_string), output));

	//fprintf(output, "Hello world!");

	res = CC20_ERR_NONE;
	fail:
	if(output) fclose(output);
	return (int)res;
}
