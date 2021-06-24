#ifndef _CC20_H
#define _CC20_H
#include <stdint.h>
#include <stddef.h>

#define KEY_SIZE 32
#define IV_SIZE 12

enum cc20_mode {
	CC20_ENCRYPT,
	CC20_DECRYPT,
};

typedef enum cc20_error {
	CC20_ERR_PANIC = -1,
	CC20_ERR_NONE = 0,

	CC20_ERR_INVALID_FILE,
	CC20_ERR_NULL_PTR,
	CC20_ERR_SSL,
	CC20_ERR_IO
} cc20_result_t;

#define CC20_OK(v) ((v)==CC20_ERR_NONE)
#define CC20_ERR(v) ((v)!=CC20_ERR_NONE)

typedef uint8_t cc20_key_t[KEY_SIZE];
typedef uint8_t cc20_iv_t[IV_SIZE];

typedef struct cc20_metadata {
	FILE* backing;
	cc20_key_t key;
	cc20_iv_t iv;
	enum cc20_mode mode;
} cc20_meta_t;

struct cc20_wrap_cfg {
	// default: false (0)
	int keep_alive;
};

typedef struct cc20_sink cc20_sink_t;

// Functions //
#define _cc20_OUT *restrict

cc20_result_t cc20_keygen(cc20_key_t* restrict key,
		cc20_iv_t* restrict iv);

cc20_result_t cc20_gen_meta(FILE* file,
		const cc20_key_t* key,
		const cc20_iv_t* iv,
		enum cc20_mode mode,
		struct cc20_metadata _cc20_OUT output);

cc20_result_t cc20_gen_sink(const struct cc20_metadata* meta,
			cc20_sink_t* _cc20_OUT output);


cc20_result_t cc20_gen_sink_full(FILE* file, 
		const cc20_key_t* key,
		const cc20_iv_t* iv,
		enum cc20_mode mode,
		cc20_sink_t* _cc20_OUT output);

cc20_result_t cc20_wrap_full(FILE* file, 
		const cc20_key_t* key,
		const cc20_iv_t* iv,
		enum cc20_mode mode,
		FILE* _cc20_OUT output);

cc20_result_t cc20_gen(const struct cc20_metadata* meta,
		FILE* _cc20_OUT output);

cc20_result_t cc20_close_sink(cc20_sink_t* sink,
		struct cc20_metadata* restrict meta);

cc20_result_t cc20_write(const void* ptr, size_t * restrict bytes, cc20_sink_t* restrict sink);

FILE* cc20_wrap_sink(cc20_sink_t* sink, const struct cc20_wrap_cfg* cfg);

#endif /* _CC20_H */
