#ifndef _CC20_H
#define _CC20_H

#ifdef __cplusplus
extern "C" {
#define restrict __restrict__
#endif

#include <stdint.h>
#include <stddef.h>

#define KEY_SIZE 32
#define IV_SIZE 12

enum cc20_mode {
	/// Encrypt the data written to this stream
	CC20_ENCRYPT,
	/// Decrypt the data written to this stream
	CC20_DECRYPT,
};

/// Result from a `cc20_` internal operation.
typedef enum cc20_error {
	/// An internal fatal error
	CC20_ERR_PANIC = -1,
	/// Operation succeeded
	CC20_ERR_NONE = 0,

	/// If a `FILE*` stream is used that is invalid or `NULL`.
	CC20_ERR_INVALID_FILE,
	/// If a pointer is `NULL` that should not be
	CC20_ERR_NULL_PTR,
	/// An underlying `libssl` call fails
	CC20_ERR_SSL,
	/// There is a generic I/O failure
	CC20_ERR_IO
} cc20_result_t;

#define CC20_OK(v) ((v)==CC20_ERR_NONE)
#define CC20_ERR(v) ((v)!=CC20_ERR_NONE)

/// A chacha20_poly1305 key
typedef uint8_t cc20_key_t[KEY_SIZE];
/// A chacha20_poly1305 IV
typedef uint8_t cc20_iv_t[IV_SIZE];

/// Metadata used to construct an instance of `cc20_sink_t`.
typedef struct cc20_metadata {
	/// A valid, non-NULL, stream that the sink will write the transformed data to.
	FILE* backing;
	/// The key used for the cipher
	cc20_key_t key;
	/// The iv used to initialise the cipher.
	cc20_iv_t iv;
	/// The transformation mode
	///
	/// *MUST* be a valid `enum cc20_mode` disctiminant or UB.
	enum cc20_mode mode;
} cc20_meta_t;

/// Configuration for a wrapper `FILE*` stream over a `cc20_sink_t`.
struct cc20_wrap_cfg {
	/// Keep the backing (`cc20_meta_t.backing`) stream alive (do not `fclose()` it) when the wrapper is closed.
	/// # Default
	///  * false (0)
	int keep_alive;
};

/// An opaque type containing the cipher transform and the backing stream.
typedef struct cc20_sink cc20_sink_t;

// Functions //

/// Parameters tagged with this must be valid, non-NULL and non-aliased; but can point to uninitialised memory for this type.
/// They are guaranteed to be written to with a valid value if the function succeeds. If it fails, it is unspecified whether it will be written to.
//TODO: Attribute non-NULL how?
#define _cc20_OUT *restrict

/// Generate a new securely random key and/or iv.
///
/// # Possible errors
/// * `CC20_ERR_PANIC` - If the RNG fails.
cc20_result_t cc20_keygen(cc20_key_t* restrict key,
		cc20_iv_t* restrict iv);

/// Write these parameters to `output` metadata.
///  * `key` and `iv` can be NULL, if one or both are, the field(s) will be initialised to secure random data in the `output` metadata (same as `cc20_keygen`.
///  * `file` must be non-NULL and valid.
/// # Possible errors
///  * `CC20_ERR_INVALID_FILE` - if `file` is NULL.
///  * `CC20_ERR_NULL_PTR` - if `output` is NULL. (see `_cc20_OUT`.)
/// ## Undefined behaviour
/// If `mode` is not a valid distriminant of `enum cc20_mdoe`.
cc20_result_t cc20_gen_meta(FILE* file,
		const cc20_key_t* key,
		const cc20_iv_t* iv,
		enum cc20_mode mode,
		struct cc20_metadata _cc20_OUT output);

/// Create a sink from the specified metadata and write it to `output`.
///
/// # Possible errors
///  * `CC20_ERR_NULL_PTR` - If `meta` or `output` is NULL.
cc20_result_t cc20_gen_sink(const struct cc20_metadata* meta,
			cc20_sink_t* _cc20_OUT output);

//TODO: Rework this entire API interface. Its clunky.
//TODO: Document the rest
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

#ifdef __cplusplus
}
#undef restrict
#endif

#endif /* _CC20_H */
