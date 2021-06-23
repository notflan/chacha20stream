#ifndef _CC20_H
#define _CC20_H

#define KEY_SIZE 32
#define IV_SIZE 12

enum cc20_mode {
	CC20_ENCRYPT,
	CC20_DECRYPT,
};

typedef uint8_t cc20_key_t[KEY_SIZE];
typedef uint8_t cc20_iv_t[IV_SIZE];

struct cc20_metadata {
	FILE* backing;
	cc20_key_t key;
	cc20_iv_t iv;
	enum cc20_mode mode;
};

typedef struct cc20_sink cc20_sink_t;

int cc20_gen_meta(FILE* file,
		const cc20_key_t* key,
		const cc20_iv_t* iv,
		enum cc20_mode mode,
		struct cc20_metadata* restrict output);

cc20_sink_t* cc20_gen_sink(const struct cc20_metadata* meta);
cc20_sink_t* cc20_gen_sink_full(FILE* file, 
		const cc20_key_t* key,
		const cc20_iv_t* iv,
		enum cc20_mode mode);
FILE* cc20_wrap(FILE* file, 
		const cc20_key_t* key,
		const cc20_iv_t* iv,
		enum cc20_mode mode);
int cc20_close_sink(cc20_sink_t* sink,
		struct cc20_metadata* restrict meta);

FILE* cc20_wrap_sink(cc20_sink_t* sink);

size_t cc20_write(const void* ptr, size_t size, size_t nmemb, cc20_sink_t* restrict sink);

#endif /* _CC20_H */
