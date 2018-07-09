/* crypto_fl.c
 *
 * SQLCipher Cryptographic Interface for SafeZone FIPS Lib
 */

/*****************************************************************************
* Copyright (c) 2014 INSIDE Secure Oy. All Rights Reserved.
*
* This confidential and proprietary software may be used only as authorized
* by a licensing agreement from INSIDE Secure.
*
* The entire notice above must be reproduced on all authorized copies that
* may only be made to the extent permitted by a licensing agreement from
* INSIDE Secure.
*
* For more information or support, please go to our online support system at
* https://essoemsupport.insidesecure.com.
* In case you do not have an account for this system, please send an e-mail to
* ESSEmbeddedHW-Support@insidesecure.com.
*****************************************************************************/

#ifndef SQLITE_OS_UNIX
/* These lines are for "standalone compilation": testing crypto_fl.c without
   the rest of SQLite and SQLCipher. */
#define SQLITE_HAS_CODEC    /* Use SQLCipher */
#define SQLCIPHER_CRYPTO_FL /* Use SafeZone FIPS Lib cryptographic interface. */
#define SQLCIPHER_FL_MAIN   /* Enable "main" function. */
#endif /* SQLITE_OS_UNIX */

/* BEGIN SQLCIPHER */
#ifdef SQLITE_HAS_CODEC
#ifdef SQLCIPHER_CRYPTO_FL
#include "fl.h"
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#if defined SQLCIPHER_FL_MAIN && defined SQLCIPHER_FL_ENSURE_LOCK_MEMORY
/* Emulate SQLITE3 api and ensure lock/memory allocations are
   freed correctly. */

/* Emulate SQLITE3's functions and constants. */
#define SQLITE_OK           0   /* Successful result */
#define SQLITE_ERROR        1   /* SQL error or missing database */
#define SQLITE_NOMEM        7   /* A malloc() failed */

#define sqlite3_mutex_enter(x) do { } while (0)
#define sqlite3_mutex_leave(x) do { } while (0)
static int sqlcipher_allocated = 0;
static void *sqlcipher_malloc(size_t sz)
{
	void *ptr = malloc(sz);
	if (ptr)
		sqlcipher_allocated += sz;
	return ptr;
}
static void sqlcipher_free(void *ptr, size_t sz)
{
	free(ptr);
	if (ptr)
		sqlcipher_allocated -= sz;
}
static enum { NO_LOCK, RD_LOCK, WR_LOCK } sqlcipher_fl_locked = NO_LOCK;
#define ENSURE(X)							\
	do {								\
		if (!(X)) {						\
			printf("ABORT: func=%s: %s\n", __func__, #X);	\
			abort();					\
		}							\
	} while (0)
#define pthread_rwlock_wrlock(x) \
	({ int ret = pthread_rwlock_wrlock(x); \
		ENSURE(sqlcipher_fl_locked == NO_LOCK); \
		sqlcipher_fl_locked = WR_LOCK; \
		ret; })
#define pthread_rwlock_rdlock(x) \
	({ int ret = pthread_rwlock_rdlock(x); \
		ENSURE(sqlcipher_fl_locked == NO_LOCK); \
		sqlcipher_fl_locked = RD_LOCK; \
		ret; })
#define pthread_rwlock_unlock(x) \
	({ int ret = pthread_rwlock_unlock(x); \
		ENSURE(sqlcipher_fl_locked != NO_LOCK); \
		sqlcipher_fl_locked = NO_LOCK; \
		ret; })

static unsigned int sqlcipher_fl_assets_used = 0;
#define SQLCIPHER_FL_INT_LOCKED() ENSURE(sqlcipher_fl_locked != NO_LOCK)
#define SQLCIPHER_FL_INT_WRLOCKED() ENSURE(sqlcipher_fl_locked == WR_LOCK)
#define SQLCIPHER_FL_INT_NO_MEM_ALLOCATED() assert(sqlcipher_allocated == 0)
#define SQLCIPHER_FL_ASSETS_ENSURE_MAX(n) ENSURE(sqlcipher_fl_assets_used <= n)
#define SQLCIPHER_FL_ASSETS_ALLOCATED(rv, n)		\
	do {						\
		if (rv == FLR_OK)			\
			sqlcipher_fl_assets_used += n;	\
	} while (0)
#define SQLCIPHER_FL_ASSETS_FREED(n) (sqlcipher_fl_assets_used -= n)
#elif defined SQLCIPHER_FL_MAIN
/* Emulate SQLITE3 api, but do not test lock/memory allocations correctness. */

/* Emulate SQLITE3's functions and constants. */
#define SQLITE_OK           0   /* Successful result */
#define SQLITE_ERROR        1   /* SQL error or missing database */
#define SQLITE_NOMEM        7   /* A malloc() failed */

#define sqlite3_mutex_enter(x) do { } while (0)
#define sqlite3_mutex_leave(x) do { } while (0)

static void *sqlcipher_malloc(size_t sz)
{
	void *ptr = malloc(sz);
	return ptr;
}
static void sqlcipher_free(void *ptr, size_t sz)
{
	free(ptr);
}

#define SQLCIPHER_FL_INT_LOCKED() do { } while (0)
#define SQLCIPHER_FL_INT_WRLOCKED() do { } while (0)
#define SQLCIPHER_FL_INT_NO_MEM_ALLOCATED() do { } while (0)
#define SQLCIPHER_FL_ASSETS_ENSURE_MAX(n) do { } while (0)
#define SQLCIPHER_FL_ASSETS_ALLOCATED(rv, n) do { } while (0)
#define SQLCIPHER_FL_ASSETS_FREED(n) do { } while (0)
#else
/* Using crypto_fl.c inside SQLCipher. Disable the features used for
   standalone test build. */
#include "sqliteInt.h"
#include "crypto.h"
#include "sqlcipher.h"

#define SQLCIPHER_FL_INT_LOCKED() do { } while (0)
#define SQLCIPHER_FL_INT_WRLOCKED() do { } while (0)
#define SQLCIPHER_FL_INT_NO_MEM_ALLOCATED() do { } while (0)
#define SQLCIPHER_FL_ASSETS_ENSURE_MAX(n) do { } while (0)
#define SQLCIPHER_FL_ASSETS_ALLOCATED(rv, n) do { } while (0)
#define SQLCIPHER_FL_ASSETS_FREED(n) do { } while (0)
#endif /* SQLITE_OS_UNIX */

/* Predefined constants. */
#define SQLCIPHER_FL_HMAC_LEN 20    /* Length of HMAC-SHA-1 output (do not
				       change). */
#define SQLCIPHER_FL_MAX_KEY_LEN 64 /* Prepared to handle up-to 512 bit keys. */
#define SQLCIPHER_FL_KEY_HASH_SIZE 8 /* Amount of keys stored in the hash. */
#define SQLCIPHER_ENTROPY_INPUT_SIZE (512 / 8) /* Amount of entropy input from
						  the entropy source (bytes). */
#define SQLCIPHER_FL_USE_DEV_URANDOM /* Use /dev/urandom as entropy source. */
#define SQLCIPHER_FL_SELFTEST /* Perform sqlcipher_fl selftest, which will take
				 only little to execute, but test all
				 sqlcipher_fl_* functions (briefly). */
static int fl_dbg = 0; /* Set to 1 to enable debugging. */

/* Debugging, with support for g_debug global to decide if debugging is
   output or not. */
#define FLDBG(fmt, ...)					\
	do {						\
		if (fl_dbg)				\
			printf(fmt "\n", __VA_ARGS__);	\
	} while (0)

typedef const struct {
	const char *cipher_name;
	const FL_Algorithm_t alg_enc;
	const FL_Algorithm_t alg_dec;
	const FL_KeyLen_t keylen;
	const FL_DataLen_t ivlen;
	const FL_DataLen_t blocklen;
} fl_cipherinfos;

typedef struct {
	fl_cipherinfos *cipher_info;
	FL_StateAsset_t state;
} fl_ctx;

/* Initialization count for the SQLCipher FIPS Lib interface. */
static unsigned int fl_init_count = 0;

/* Database for information on ciphers provided by FIPS Lib. */
static const fl_cipherinfos fl_cipherinfos_db[] = {
	{ "AES-128-CBC",
	  FL_ALGO_CBC_AES_ENCRYPT, FL_ALGO_CBC_AES_DECRYPT, 16, 16, 16 },
	{ "AES-192-CBC",
	  FL_ALGO_CBC_AES_ENCRYPT, FL_ALGO_CBC_AES_DECRYPT, 24, 16, 16 },
	{ "AES-256-CBC",
	  FL_ALGO_CBC_AES_ENCRYPT, FL_ALGO_CBC_AES_DECRYPT, 32, 16, 16 },
	{ "AES-128-ECB",
	  FL_ALGO_ECB_AES_ENCRYPT, FL_ALGO_ECB_AES_DECRYPT, 16, 0, 16 },
	{ "AES-192-ECB",
	  FL_ALGO_ECB_AES_ENCRYPT, FL_ALGO_ECB_AES_DECRYPT, 24, 0, 16 },
	{ "AES-256-ECB",
	  FL_ALGO_ECB_AES_ENCRYPT, FL_ALGO_ECB_AES_DECRYPT, 32, 0, 16 },
	{ NULL, 0, 0, 0, 0, 0 }
};

/* Per thread mapping between key and associated asset. */
/* Single state object per thread. */
struct sqlcipher_fl_int_keyasset {
	FL_KeyAsset_t KeyAsset;
	/* matching key is the next three fields. */
	FL_PolicyFullBits_t policy;
	uint32_t      keylen; /* 0 when not in use */
	uint8_t       key[SQLCIPHER_FL_MAX_KEY_LEN];
};

#define SQLCIPHER_FL_KEY_HASH(keydata) \
	((keydata)[0] % SQLCIPHER_FL_KEY_HASH_SIZE)

/* Cached assets. */
static struct sqlcipher_fl_int_keyasset sqlcipher_fl_int_assets[
	SQLCIPHER_FL_KEY_HASH_SIZE];

#ifndef SQLCIPHER_FL_NO_THREADS
/* Lock for manipulating caches assets. */
static pthread_rwlock_t asset_store_lock;
#endif

/* Shared state object. */
static FL_StateAsset_t fl_global_state;

/* Return value conversion.
   FIPS Lib uses FL_RV, sqlcipher uses SQLITE #define's. */
static inline int sqlcipher_fl_rv_convert(FL_RV rv)
{
	return rv == FLR_OK ? SQLITE_OK : SQLITE_ERROR;
}

/* Create state object. */
static
FL_RV
sqlcipher_fl_int_new_state(FL_AnyAsset_t *asset_p)
{
	FL_RV rv;
	/* Note: SQLCIPHER_FL_INT_WRLOCKED();
	   omitted, because the function is also invoked during
	   initialization before the wr-lock is available to be used. */
	rv = FL_ALLOCATE_STATE(asset_p);
	SQLCIPHER_FL_ASSETS_ALLOCATED(rv, 1);
	return rv;
}

/* Global initialization. This contains ensuring FL is initialized.
   There is no corresponding uninitialization. This is intentional:
   The FIPS 140-2 required self-testing takes some time and if library
   is every fully uninitialized, the testing needs to be redone. Instead,
   the library is initialized once, and after that it can be assumed to be
   initialized. The library unitialization will anyway happen automatically,
   once the process exists. */
static int sqlcipher_fl_int_init(void)
{
	FL_RV rv = FLR_OK;
	static int sqlcipher_fl_initialized = 0;

#ifndef SQLCIPHER_FL_NO_THREADS
	static pthread_mutex_t sqlcipher_fl_init_mutex =
		PTHREAD_MUTEX_INITIALIZER;
#endif /* SQLCIPHER_FL_NO_THREADS */

#ifndef SQLCIPHER_FL_NO_THREADS
	/* Use initialization mutex to protect from concurrency. */
	if (pthread_mutex_lock(&sqlcipher_fl_init_mutex) != 0)
		return SQLITE_ERROR; /* Failed to acquire mutex. */
#endif /* SQLCIPHER_FL_NO_THREADS */

	/* Initialize the library. If the library is not already initialized,
	   this function will run selftests for the library which takes a
	   while to execute. */
	rv = FL_LibInit();

	/* Accept either "initialized now" or "already initialized". */
	if (rv == FLR_WRONG_STATE)
		rv = FLR_OK;

	if (rv == FLR_OK && !sqlcipher_fl_initialized) {
		/* Start with cleaned asset table. */
		memset(&sqlcipher_fl_int_assets, 0,
		       sizeof(sqlcipher_fl_int_assets));

#ifndef SQLCIPHER_FL_NO_THREADS
		/* Allocate locks to protect multithreaded execution. */
		if (pthread_rwlock_init(&asset_store_lock, NULL))
			rv = FLR_OPERATION_FAILED;
#endif /* SQLCIPHER_FL_NO_THREADS */

		/* Allocate one state object, which can be used for single
		   threaded work. Each ctx will have their own "per ctx"
		   state. */
		if (rv == FLR_OK)
			rv = sqlcipher_fl_int_new_state(&fl_global_state);

		if (rv == FLR_OK)
			sqlcipher_fl_initialized = 1; /* The library will be
							 initialized for the
							 lifetime of the
							 process. */
	}

#ifndef SQLCIPHER_FL_NO_THREADS
	(void)pthread_mutex_unlock(&sqlcipher_fl_init_mutex);
#endif /* SQLCIPHER_FL_NO_THREADS */

	return sqlcipher_fl_rv_convert(rv);
}

/* Finish FL processing started with sqlcipher_fl_int_process* functions. */
static void sqlcipher_fl_int_done(void)
{
#ifndef SQLCIPHER_FL_NO_THREADS
	pthread_rwlock_unlock(&asset_store_lock); /* Assumed to never fail. */
#endif /* SQLCIPHER_FL_NO_THREADS */
}

/* Start FL processing allowing multithreaded access (Read-only lock).

   Multithreaded access is only available for fast functions, which do not
   manipulate any other FL state except the state of the context used
   in the function call. It is not allowed to add/remove keys or generate
   random values directly or indirectly.

   When finished the lock MUST be freed via sqlcipher_fl_int_done().
*/
static void sqlcipher_fl_int_process_parallel(void)
{
#ifndef SQLCIPHER_FL_NO_THREADS
	pthread_rwlock_rdlock(&asset_store_lock); /* Assumed to never fail. */
#endif /* SQLCIPHER_FL_NO_THREADS */
}

/* Start FL processing disallowing multithreaded access (Read/write lock).

   This lock needs to be obtained to perform operations with FL, except for
   small subset of operations allowed by sqlcipher_fl_int_process_parallel.

   When finished the lock MUST be freed via sqlcipher_fl_int_done().
 */
static FL_StateAsset_t sqlcipher_fl_int_process(void)
{
#ifndef SQLCIPHER_FL_NO_THREADS
	if (pthread_rwlock_wrlock(&asset_store_lock))
		return FL_ASSET_INVALID;
#endif /* SQLCIPHER_FL_NO_THREADS */

	return fl_global_state;
}

/* Create key object (on FL's Asset Store).
   The function is given key material as array+length and key attributes
   as keysz+length. For current key formats supported by the FIPS Lib,
   the function will fail and return FL_ASSET_INVALID if array length and
   key length differs. */
static
FL_AnyAsset_t
sqlcipher_fl_int_new_key(const void *array, size_t arraysz, size_t keysz,
			 FL_PolicyFullBits_t policy)
{
	FL_AnyAsset_t asset = FL_ASSET_INVALID;
	FL_RV rv;

	SQLCIPHER_FL_INT_WRLOCKED(); /* Adding new keys requires write lock. */

	if (keysz > SQLCIPHER_FL_MAX_KEY_LEN)
		return FL_ASSET_INVALID;

	/* Allocate key */
	rv = FL_AssetAllocate(
		policy,
		(uint32_t)keysz,
		FL_POLICY_MASK_ANY,
		&asset);
	SQLCIPHER_FL_ASSETS_ALLOCATED(rv, 1);

	/* (Optionally) load key material. */
	if (rv == FLR_OK && array != NULL) {
		rv = FL_AssetLoadValue(asset, array, arraysz);
		if (rv != FLR_OK) {
			(void)FL_AssetFree(asset);
			SQLCIPHER_FL_ASSETS_FREED(1);
			asset = FL_ASSET_INVALID;
		}
	}
	return asset;
}

typedef uint32_t uint32_pair_t[2];

static const uint8_t AES_KW_InitialValue[8] = {
	0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};

/* Unwrap key using AES-KW algorithm.

   Note: the function is only for key sizes, which are multiple of 8 bytes. */
static FL_RV sqlcipher_fl_int_aes_unwrap(FL_AnyAsset_t state,
					 FL_AnyAsset_t key,
					 uint32_pair_t *data_tmp,
					 size_t bytes_in)
{
	FL_RV rv;
	uint32_pair_t *R;
	union {
		/* A and B variables, combined storage */
		uint8_t A_bytes[16];
		uint32_t A[2];
		uint8_t B_bytes[16];
		uint32_t B[4];
	} u;
	int i;
	int j;
	uint16_t cnt;
	uint32_t n;

	/* Handling requires input is multiple of 8 and at least 24. */
	if (bytes_in < 24 || (bytes_in & 7) != 0)
		return FLR_INVALID_ARGUMENTS;

	R = &data_tmp[1];
	memcpy(u.A_bytes, data_tmp, 8);
	n = bytes_in - 8;

	n /= 8; /* n == number of blocks. */

	rv = FL_CipherInit(key, state, FL_ALGO_ECB_AES_DECRYPT, NULL, 0);

	for (j = 5; j >= 0; j--) {
		for (i = n; i >= 1; i--) {
			u.B[2] = R[i - 1][0];
			u.B[3] = R[i - 1][1];
			cnt = (uint16_t)(n * j + i);
			u.A_bytes[7] ^= cnt & 255;
			u.A_bytes[6] ^= cnt >> 8;

			if (rv == FLR_OK)
				rv = FL_CipherContinue(state, u.B_bytes,
						       u.B_bytes, 16);

			R[i - 1][0] = u.B[2];
			R[i - 1][1] = u.B[3];
		}
	}

	if (rv == FLR_OK)
		rv = FL_CipherFinish(state);

	if (rv == FLR_OK) {
		/* Compare against initial value or provided alternative
		   initial value. */
		rv = memcmp(&(u.A_bytes[0]), AES_KW_InitialValue, 8) == 0 ?
			FLR_OK : FLR_VERIFY_MISMATCH;
	}

	/* Clear temporaries. */
	memset(&u, 0, sizeof(u));

	return rv;
}

#ifdef SQLCIPHER_FL_USE_DEV_URANDOM
/* Use /dev/urandom as entropy source. */
static const char EntropyDeviceDefault[] = "/dev/urandom";
static const char *EntropyDevice_p = EntropyDeviceDefault;
static int sqlcipher_fl_int_HasLastEntropy;
/* Handle provided input source via FIPS 140-2 style conditional input test,
   to ensure that if entropy source gets stuck (starts to return same block),
   it is properly detected as entropy source failure. */
static size_t sqlcipher_fl_int_FileInputConditionalTest(
	FL_DataOutPtr_t out_p,
	size_t sz,
	FILE *file)
{
	static FL_Data_t lastEntropy[16]; /* block size 16 bytes == 128 bits. */
	int i;
	FL_Data_t diffmask;

	if (sz == 0)
		return 0; /* read size should be larger than 0 */

	while (sz > 0) {
		if (!sqlcipher_fl_int_HasLastEntropy) {
			/* first block, read to lastEntropy. */
			if (fread(lastEntropy, 16, 1, file) != 1)
				return 0;

			sqlcipher_fl_int_HasLastEntropy = 1;
		} else {
			/* subsequent block => compare. */
			if (fread(out_p, 16, 1, file) != 1)
				return 0;

			/* compare against previous block and store this
			   block for next comparison. */
			diffmask = 0;
			for (i = 0; i < 16; i++) {
				/* diffmask stays 0 only if lastEntropy[i] and
				   out_p[i] are the same. */
				diffmask |= lastEntropy[i] ^ out_p[i];
				/* replace lastEntropy[i] with out_p[i]. */
				lastEntropy[i] = out_p[i];
			}

			/* diffmask is 0 only if lastEntropy was equal to out_p.
			   In that case return 0 (error), because the
			   conditional test failed. */
			if (diffmask == 0)
				return 0;

			/* Increment block counter. */
			out_p += 16;
			sz -= 16;
		}
	}

	return 1;
}

/* Read entropy from entropy source and return entropy estimate.

   This function implements the interface FL_RbgInstallEntropySource
   requires for entropy input function. */
static void sqlcipher_fl_int_entropy_input_from(
	const char      *Device_p,
	FL_DataOutPtr_t  EntropyOut_p,
	FL_DataLen_t     BufferSize,
	FL_DataLen_t    *InputSize,
	FL_BitsLen_t    *EntropySize)
{
	FILE *f = fopen(Device_p, "r");
	*InputSize = 0;
	*EntropySize = 0;

	if (f == NULL)
		return;

	/* Make input unbuffered. */
	setvbuf(f, NULL, _IONBF, 0);

	if (BufferSize > SQLCIPHER_ENTROPY_INPUT_SIZE)
		/* The function at most provides SQLCIPHER_ENTROPY_INPUT_SIZE
		   bytes. */
		BufferSize = SQLCIPHER_ENTROPY_INPUT_SIZE;

	BufferSize &= ~15; /* Make BufferSize multiple of 128-bits. */

	/* Read file input with simple test: detect duplicate 128-bit blocks. */
	if (sqlcipher_fl_int_FileInputConditionalTest(EntropyOut_p,
						      BufferSize, f)) {
		*InputSize = BufferSize;
		*EntropySize = BufferSize * 8; /* Assume entropy acquired ==
						  number of bits. */
	}

	fclose(f);
}

/* Entropy input function.
   This function implements the interface FL_RbgInstallEntropySource
   requires for entropy input function. */
static void sqlcipher_fl_int_entropy_input(FL_DataOutPtr_t  EntropyOut_p,
					   FL_DataLen_t     BufferSize,
					   FL_DataLen_t    *InputSize,
					   FL_BitsLen_t    *EntropySize)
{
	sqlcipher_fl_int_entropy_input_from(EntropyDevice_p,
					    EntropyOut_p,
					    BufferSize,
					    InputSize,
					    EntropySize);
}

/* sqlcipher_fl_int_process_random is just like sqlcipher_fl_int_process,
   but the function is used when random numbers are used in the processing
   or DRBG state is changes (reseeding).

   sqlcipher_fl_int_process_random differs from sqlcipher_fl_int_process in
   that it loads alternative entropy before processing, if it has not been
   loaded yet. */
static FL_StateAsset_t sqlcipher_fl_int_process_random(void)
{
	static int sqlcipher_fl_int_random_initialized = 0;

	FL_StateAsset_t state = sqlcipher_fl_int_process();

	/* Prepare rbg if this is the first use of the rbg. */
	if (state != FL_ASSET_INVALID &&
	    sqlcipher_fl_int_random_initialized == 0) {
		FL_RV rv = FL_RbgInstallEntropySource(
			sqlcipher_fl_int_entropy_input);

		if (rv == FLR_OK) {
			sqlcipher_fl_int_random_initialized = 1;
		} else {
			/* Error detected. */
			sqlcipher_fl_int_done();
			state = FL_ASSET_INVALID;
		}
	}

	return state; /* state object to use or FL_ASSET_INVALID on failure. */
}
#else
/* If default RBG entropy source is used, sqlcipher_fl_int_process_random
   is actually exactly the same than sqlcipher_fl_int_process. */
#define sqlcipher_fl_int_process_random sqlcipher_fl_int_process
#endif /* SQLCIPHER_FL_USE_DEV_URANDOM */

/* Export an exportable key from SafeZone FIPS Lib key store.

   Exporting key is done as two part operation:

   * The key is exported as encrypted key.
   * The exported encrypted key is decrypted.

   It is neccessary to perform this operation in
   two steps as the asset store does not allow
   to directly export as plaintext key.

   Note: If key policy prevents exporting key, then it cannot be exported
   with this function. Only keys with FL_POLICY_FLAG_EXPORTABLE are ok to
   export. */
static
FL_RV
sqlcipher_fl_int_export(FL_StateAsset_t state,
			FL_AnyAsset_t asset,
			void *array)
{
	/* The export/import operations use temporary key.
	   It is not important what key material the key has, but it must
	   be 128-bit, 192-bit or 256-bit.
	 */
	static unsigned char export_key[16] = {
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	};
	FL_DataLen_t Len;
	uint32_pair_t tmp[128 / sizeof(uint32_pair_t)] = { { 0, 0 } };
	FL_RV rv = FLR_OPERATION_FAILED;
	FL_AnyAsset_t key;

	SQLCIPHER_FL_INT_WRLOCKED();

	key = sqlcipher_fl_int_new_key(
		export_key, 16, 16,
		FL_POLICY_ALGO_AES_WRAP_WRAP |
		FL_POLICY_ALGO_ECB_AES_DECRYPT);

	if (key != FL_ASSET_INVALID) {
		rv = FL_AssetsWrapAes(key, &asset, 1,
				      (void *)&tmp, (FL_DataLen_t) sizeof(tmp),
				      &Len);

		if (rv == FLR_OK) {
			rv = sqlcipher_fl_int_aes_unwrap(state,
							 key, tmp,
							 (size_t) Len);
		}
		if (rv == FLR_OK) {
			memcpy(array, &tmp[1], Len - 8);
			memset(tmp, 0, Len);
		}
		(void) FL_AssetFree(key);
		SQLCIPHER_FL_ASSETS_FREED(1);
	}
	return rv;
}

/* Clean key cache. This function is useful to release allocated resources
   from the cache. */
static void sqlcipher_fl_int_unmap_keys(void)
{
	int keyslot;

	SQLCIPHER_FL_INT_WRLOCKED();

	/* Free and uninitialize all cached keys. */
	for (keyslot = 0; keyslot < SQLCIPHER_FL_KEY_HASH_SIZE; keyslot++) {
		if (sqlcipher_fl_int_assets[keyslot].KeyAsset !=
		    FL_ASSET_INVALID) {
			(void)FL_AssetFree(
				sqlcipher_fl_int_assets[keyslot].KeyAsset);
			SQLCIPHER_FL_ASSETS_FREED(1);
			sqlcipher_fl_int_assets[keyslot].keylen = 0;
			sqlcipher_fl_int_assets[keyslot].KeyAsset =
				FL_ASSET_INVALID;
			sqlcipher_fl_int_assets[keyslot].policy =
				(FL_PolicyFullBits_t) 0;
			memset(sqlcipher_fl_int_assets[keyslot].key, 0,
			       sizeof(sqlcipher_fl_int_assets[keyslot].key));
		}
	}
}

/* Make specified key available or use cached key.

   FIPS Lib memory management requires global lock and memory management
   happens when new keys are added / removed. This function tries to remove
   some of that: keys used are cached inside the asset store so that if the
   same key is reused, only key reference is returned.

   If key is successfully returned, the thread has a lock, as obtained by
   sqlcipher_fl_int_process_parallel(); or sqlcipher_fl_int_process().
   It is neccessary to call sqlcipher_fl_int_done() to free the lock.

   (No lock is held if operation fails, for instance because length of the
   key exceeds maximum SQLCIPHER_FL_MAX_KEY_LEN). */
static FL_KeyAsset_t sqlcipher_fl_int_map_key(const uint8_t key[],
					      uint32_t keylen,
					      FL_PolicyFullBits_t policy)
{
	int keyslot;
	FL_RV rv;
	FL_KeyAsset_t id;

	/* No key material or too long key. */
	if (keylen == 0 || keylen > SQLCIPHER_FL_MAX_KEY_LEN)
		return FL_ASSET_INVALID;

	sqlcipher_fl_int_process_parallel();

	/* Find slot with the key and the policy. */
	keyslot = SQLCIPHER_FL_KEY_HASH(key);
	if (keylen == sqlcipher_fl_int_assets[keyslot].keylen &&
	    policy == sqlcipher_fl_int_assets[keyslot].policy &&
	    !memcmp(key, sqlcipher_fl_int_assets[keyslot].key, keylen)) {
		/* The key is already available. */
		FLDBG("Reusing previous loaded key (id=0x%x)",
		      (unsigned) sqlcipher_fl_int_assets[keyslot].KeyAsset);
		return sqlcipher_fl_int_assets[keyslot].KeyAsset;
	}

	/* Upgrade the lock to write-lock. This actually requires to free
	   the lock and acquire new lock. */
	sqlcipher_fl_int_done();
	if (sqlcipher_fl_int_process() == FL_ASSET_INVALID)
		return FL_ASSET_INVALID;

	/* Free possible preexisting key. */
	if (sqlcipher_fl_int_assets[keyslot].KeyAsset != FL_ASSET_INVALID) {
		FL_AssetFree(sqlcipher_fl_int_assets[keyslot].KeyAsset);
		SQLCIPHER_FL_ASSETS_FREED(1);
	}

	id = sqlcipher_fl_int_new_key(key, keylen, keylen, policy);
	sqlcipher_fl_int_assets[keyslot].KeyAsset = id;

	if (id != FL_ASSET_INVALID) {
		/* setup key fields for next match. */
		sqlcipher_fl_int_assets[keyslot].keylen = keylen;
		sqlcipher_fl_int_assets[keyslot].policy = policy;
		memcpy(sqlcipher_fl_int_assets[keyslot].key, key, keylen);

		FLDBG("Allocated and loaded key, id=%#x policy=%#x keylen=%d",
		      (unsigned int) sqlcipher_fl_int_assets[keyslot].KeyAsset,
		      (unsigned int) policy, (int) keylen);
		/* Lock remains (exclusive lock). */
	} else {
		FLDBG("Unable to allocate asset for key. policy=%#x keylen=%d",
		      (unsigned int) policy, (int) keylen);
		sqlcipher_fl_int_done(); /* Free lock if allocation fails. */
	}

	return id;
}

/* Activate context provided to the function and count uses of sqlcipher_fl. */
static int sqlcipher_fl_activate(void *ctx)
{
	FL_RV rv = FLR_OPERATION_FAILED;
	FL_StateAsset_t state;

	/* Support call with NULL ctx resulting from failed mem allocation. */
	if (ctx == NULL)
		return SQLITE_NOMEM;

	state = sqlcipher_fl_int_process();
	if (state != FL_ASSET_INVALID) {
		/* Initialize ctx if provided. */
		fl_ctx *c = ctx;
		c->cipher_info = NULL;
		rv = sqlcipher_fl_int_new_state(&c->state);

		fl_init_count += (rv == FLR_OK);
		sqlcipher_fl_int_done();
	}

	return (rv == FLR_OK) ? SQLITE_OK : SQLITE_ERROR;
}

/* Deactivate context provided to the function and decrement use count. */
static int sqlcipher_fl_deactivate(void *ctx)
{
	FL_StateAsset_t state = sqlcipher_fl_int_process();
	fl_ctx *c = ctx;

	if (state != FL_ASSET_INVALID) {
		fl_init_count--; /* Count open inits. */

		if (fl_init_count == 0) {
			/* Remove all cached keys. */
			sqlcipher_fl_int_unmap_keys();

			/* Intentionally not uninitializing the FIPS Lib, to
			   save cost of reinitializing.
			   The FIPS Lib uninitialize does not make any more
			   memory available, but reinitialize takes a long
			   period of time. */
		}

		/* Uninitialize ctx. */
		(void)FL_AssetFree(c->state);
		SQLCIPHER_FL_ASSETS_FREED(1);
		c->cipher_info = NULL;
		c->state = FL_ASSET_INVALID;

		sqlcipher_fl_int_done();
	}

	return state != FL_ASSET_INVALID ? SQLITE_OK : SQLITE_ERROR;
}

/* Return name of the provider. */
static const char *sqlcipher_fl_get_provider_name(void *ctx)
{
	return "fl";
}

/* Set cipher to use via the ctx.
   Supported ciphers are aes-cbc-128, aes-cbc-192, aes-cbc-256,
   aes-ecb-128, aes-ecb-192, and aes-ecb-256.

   The names of ciphers are case-insensitive. */
static int sqlcipher_fl_set_cipher(void *ctx, const char *cipher_name)
{
	fl_ctx *c = ctx;
	fl_cipherinfos *ci = &fl_cipherinfos_db[0];

	/* Find algorithm matching cipher_name. Currently
	   AES-ECB and AES-CBC are supported. */
	while (ci->cipher_name && strcasecmp(ci->cipher_name, cipher_name))
		ci++;

	/* Debug log the cipher algorithm and options used. */
	FLDBG("CIPHER: %s(op=%d,%d), %d, %d", ci->cipher_name,
	      ci->alg_enc, ci->alg_dec, ci->keylen, ci->ivlen);
	c->cipher_info = ci->cipher_name ? ci : NULL;
	return SQLITE_OK;
}

/* Get the name of the current cipher. */
static const char *sqlcipher_fl_get_cipher(void *ctx)
{
	fl_ctx *c = ctx;
	fl_cipherinfos *cipher_info = c->cipher_info;
	return cipher_info != NULL? cipher_info->cipher_name: NULL;
}

/* Generate random bits. The buffer size is expressed in bytes.
   The algorithm used for random bit generation is DRBG 800-90A, DRBG_CTR
   using AES algorithm and 256-bit key. */
static int sqlcipher_fl_random(void *ctx, void *buffer, int length)
{
	FL_RV rv = FLR_OPERATION_FAILED;
	FL_StateAsset_t state;

	state = sqlcipher_fl_int_process_random();
	if (state != FL_ASSET_INVALID) {
		rv = FL_RbgGenerateRandom(256, buffer, (FL_DataLen_t) length);
		sqlcipher_fl_int_done();
	}
	return sqlcipher_fl_rv_convert(rv);
}

/* Calculate HMAC-SHA-1 of concatenation of two provided inputs with the
   provided HMAC key. */
static int sqlcipher_fl_hmac(void *ctx, unsigned char *hmac_key, int key_sz,
			     unsigned char *in, int in_sz, unsigned char *in2,
			     int in2_sz, unsigned char *out)
{
	fl_ctx *c = ctx;
	FL_RV rv;
	FL_KeyAsset_t key;

	key = sqlcipher_fl_int_map_key(hmac_key, key_sz,
				       FL_POLICY_ALGO_HASH_SHA1 |
				       FL_POLICY_ALGO_MAC_GENERATE);

	if (key == FL_ASSET_INVALID) {
		FLDBG("Unable to allocate asset for key. keylen=%d", key_sz);
		return SQLITE_ERROR;
	}

	rv = FL_MacGenerateInit(key, c->state, FL_ALGO_HMAC_SHA1,
				in, (FL_DataLen_t) in_sz);

	if (rv == FLR_OK)
		rv = FL_MacGenerateContinue(c->state, in2, in2_sz);

	if (rv == FLR_OK)
		rv = FL_MacGenerateFinish(c->state, out, SQLCIPHER_FL_HMAC_LEN);

	sqlcipher_fl_int_done();

	return sqlcipher_fl_rv_convert(rv);
}

/* Calculate PBKDF2 key derivation algorithm using SHA-1 hash, the specified
   password, salt and workfactor (iteration count), and return the derived key.
 */
static int sqlcipher_fl_kdf(void *ctx, const unsigned char *pass, int pass_sz,
			    unsigned char *salt, int salt_sz, int workfactor,
			    int key_sz, unsigned char *key)
{
	/* Use exclusive lock for now. */
	FL_KeyAsset_t tmp;
	FL_RV rv;
	FL_StateAsset_t state;
	FL_PolicySmallBits_t policy =
		FL_POLICY_FLAG_EXPORTABLE |
		FL_POLICY_ALGO_MAC_VERIFY |
		FL_POLICY_ALGO_HMAC_SHA2_256;

	state = sqlcipher_fl_int_process();
	if (state == FL_ASSET_INVALID)
		return SQLITE_ERROR;

	/* This code uses temporary asset as key derivation target. */
	rv = FL_AssetAllocateBasic(policy, (FL_DataLen_t) key_sz, &tmp);
	SQLCIPHER_FL_ASSETS_ALLOCATED(rv, 1);

	if (rv == FLR_OK) {
		rv = FL_KeyDerivePbkdf2(FL_ALGO_HASH_SHA1,
					(FL_DataInPtr_t) pass,
					(FL_DataLen_t) pass_sz,
					(FL_DataInPtr_t) salt,
					(FL_DataLen_t) salt_sz,
					workfactor,
					tmp);

		if (rv == FLR_OK)
			rv = sqlcipher_fl_int_export(state, tmp, key);

		(void)FL_AssetFree(tmp);
		SQLCIPHER_FL_ASSETS_FREED(1);
	}

	sqlcipher_fl_int_done();

	return sqlcipher_fl_rv_convert(rv);
}

/* Encrypt or decrypt using AES cipher.
   The output buffer shall be the same size than the input buffer.
   Input size in_sz shall be multiple of AES block size (16).

   The block cipher mode of operation for AES cipher is selected using
   sqlcipher_fl_set_cipher function. It is not allowed to call this function
   without using sqlcipher_fl_set_cipher to select the mode of operation.

   The value IV must point to 16 bytes long buffer for CBC mode of operation,
   and is ignored for ECB mode of operation.
 */
static int sqlcipher_fl_cipher(void *ctx, int mode, unsigned char *key,
			       int key_sz, unsigned char *iv,
			       unsigned char *in, int in_sz,
			       unsigned char *out)
{
	fl_ctx *c = ctx;
	FL_RV rv;
	FL_KeyAsset_t asset;

	asset = sqlcipher_fl_int_map_key(key, key_sz,
					 FL_POLICY_ALGO_ECB_AES_ENCRYPT |
					 FL_POLICY_ALGO_ECB_AES_DECRYPT |
					 FL_POLICY_ALGO_CBC_AES_ENCRYPT |
					 FL_POLICY_ALGO_CBC_AES_DECRYPT);

	if (asset == FL_ASSET_INVALID) {
		FLDBG("Unable to allocate asset for key. keylen=%d", key_sz);
		return SQLITE_ERROR;
	}

	rv = FL_CipherInit(asset, c->state,
			   mode ? c->cipher_info->alg_enc :
			   c->cipher_info->alg_dec,
			   iv, c->cipher_info->ivlen);

	if (rv == FLR_OK)
		rv = FL_CipherContinue(c->state, in, out, in_sz);

	if (rv == FLR_OK)
		rv = FL_CipherFinish(c->state);

	sqlcipher_fl_int_done();

	return sqlcipher_fl_rv_convert(rv);
}

/* Add entropy to FIPS Lib's DRBG 800-90A random number generator.
   This function also invokes DRBG 800-90A reseeding operation. */
static int sqlcipher_fl_add_random(void *ctx, void *buffer, int length)
{
	FL_RV rv = FLR_OPERATION_FAILED;
	FL_StateAsset_t state;

	state = sqlcipher_fl_int_process_random();
	if (state != FL_ASSET_INVALID) {
		rv = FL_RbgReseed(buffer, (FL_DataLen_t) length);
		sqlcipher_fl_int_done();
	}
	return sqlcipher_fl_rv_convert(rv);
}

/* Get key size (in bytes).

   The function will return 16, 24 or 32, which correspond to 128-bit, 192-bit
   and 256-bit keys.

   This function can only be used if the block cipher mode of operation
   for AES cipher has been selected using sqlcipher_fl_set_cipher function.*/
static int sqlcipher_fl_get_key_sz(void *ctx)
{
	fl_ctx *c = ctx;
	return c->cipher_info->keylen;
}

/* Get IV (Initialization Vector) size (in bytes).

   The function will return 0 or 16.

   This function can only be used if the block cipher mode of operation
   for AES cipher has been selected using sqlcipher_fl_set_cipher function.*/
static int sqlcipher_fl_get_iv_sz(void *ctx)
{
	fl_ctx *c = ctx;
	return c->cipher_info->ivlen;
}

/* Get cipher block size (in bytes).

   The function will return 16 as the only currently supported cipher, AES,
   uses that block size.

   This function can only be used if the block cipher mode of operation
   for AES cipher has been selected using sqlcipher_fl_set_cipher function.*/
static int sqlcipher_fl_get_block_sz(void *ctx)
{
	fl_ctx *c = ctx;
	return c->cipher_info->blocklen;
}

/* Get the length of HMA-SHA-1 output in bytes (always returns 20). */
static int sqlcipher_fl_get_hmac_sz(void *ctx)
{
	return SQLCIPHER_FL_HMAC_LEN;
}

/* Copy context settings (including cipher mode of operation) to target_ctx. */
static int sqlcipher_fl_ctx_copy(void *target_ctx, void *source_ctx)
{
	fl_ctx *target = target_ctx;
	fl_ctx *source = source_ctx;

	target->cipher_info = source->cipher_info;
	/* target->state is not modified by copying operation. */

	return SQLITE_OK;
}

/* Compare context settings (specifically, cipher mode of operation).

   Returns 1 if the settings are the same.

   Note: Key material or cipher state is not considered by the function. */
static int sqlcipher_fl_ctx_cmp(void *c1, void *c2)
{
	fl_ctx *c1_ctx = c1;
	fl_ctx *c2_ctx = c2;

	return c1_ctx->cipher_info == c2_ctx->cipher_info;
}

/* Allocate memory for sqlcipher_fl's context and initialize the context.

   Note: The function accepts pointer to pointer unlike the most other
   functions in the API.
   Note2: sqlcipher_fl_set_cipher or sqlcipher_fl_ctx_copy is needed before
   most cipher related operations are possible with the context. */
static int sqlcipher_fl_ctx_init(void **ctx)
{
	*ctx = sqlcipher_malloc(sizeof(fl_ctx));
	return sqlcipher_fl_activate(*ctx);
}

/* End using specified context and free the memory.

   Note: The function accepts pointer to pointer unlike the most other
   functions in the API.
*/
static int sqlcipher_fl_ctx_free(void **ctx)
{
	(void) sqlcipher_fl_deactivate(*ctx);
	sqlcipher_free(*ctx, sizeof(fl_ctx));
	return SQLITE_OK;
}

#ifdef SQLCIPHER_FL_SELFTEST

/* Helper function for purposes of finding out the code coverage.
   The function intentionally counts as full coverage even if the
   failure branch is never taken. */
static void must_internal(int c, const char *fmt, const char *func,
			  const char *cond)
{
	/* This branches are never taken (except upon test failure), as
	   provided condition must be true. */
	if (!(c)) {
		printf(fmt, func, cond);
		exit(1);
	}
}
#define MUST(X)	must_internal((X), "ABORT: func=%s: %s\n", __func__, #X)

/* Perform selftesting for sqlcipher_fl. Run simple test cases of all
   the functionality of the module. */
static void sqlcipher_fl_selftest(void)
{
	void *AES_128_CBC; /* Context for AES with 128-bit key and CBC mode. */
	void *AES_192_CBC; /* Context for AES with 192-bit key and CBC mode. */
	void *AES_256_CBC; /* Context for AES with 256-bit key and CBC mode. */
	void *AES_128_ECB; /* Context for AES with 128-bit key and ECB mode. */
	void *AES_192_ECB; /* Context for AES with 192-bit key and ECB mode. */
	void *AES_256_ECB; /* Context for AES with 256-bit key and ECB mode. */
	void *AES_CBC; /* Varies what key length used, usually 256-bit key. */
	unsigned char tmp_data[32] = { 0 };
	const unsigned char hmac_kat[SQLCIPHER_FL_HMAC_LEN] = {
		0xf5, 0x0b, 0x11, 0xc1, 0xfe, 0xd1, 0xa7, 0x97, 0x7a, 0x14,
		0x03, 0x68, 0xb0, 0x0a, 0xfd, 0x3c, 0x4a, 0x1e, 0x3b, 0x72
	};
	const unsigned char kdf_kat[] = {
		0xd4, 0xc2, 0xb2, 0x64, 0xd9, 0x9c, 0x58, 0x33, 0xed, 0x83,
		0x30, 0xc0, 0xaa, 0xb0, 0x4b, 0xd0, 0x91, 0x7a, 0xf3, 0x9f,
		0x86, 0xea, 0x86, 0x2f, 0x60, 0xb6, 0xdc, 0x06, 0x27, 0xb8,
		0xa2, 0xd7
	};
	int i;

	/* Ensure FIPSLib is usable */
	MUST(sqlcipher_fl_int_init() == SQLITE_OK);
	/* Ensure FIPSLib multi-init is supported. */
	MUST(sqlcipher_fl_int_init() == SQLITE_OK);
	/* sqlcipher_fl_activate returns SQLITE_NOMEM if passed NULL pointer. */
	MUST(sqlcipher_fl_activate(NULL) == SQLITE_NOMEM);
	/* sqlcipher_fl_ctx_init/sqlcipher_fl_set_cipher testing: */
	MUST(sqlcipher_fl_ctx_init(&AES_128_CBC) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_init(&AES_192_CBC) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_init(&AES_256_CBC) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_init(&AES_128_ECB) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_init(&AES_192_ECB) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_init(&AES_256_ECB) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_init(&AES_CBC) == SQLITE_OK);

	/* sqlcipher_fl_set_cipher testing
	   (side-effect: configure &AES* contexts for later use.) */
	MUST(sqlcipher_fl_set_cipher(AES_128_CBC, "aes-128-cbc") == SQLITE_OK);
	MUST(sqlcipher_fl_set_cipher(AES_192_CBC, "AES-192-CBC") == SQLITE_OK);
	MUST(sqlcipher_fl_set_cipher(AES_256_CBC, "aes-256-cbc") == SQLITE_OK);
	MUST(sqlcipher_fl_set_cipher(AES_128_ECB, "Aes-128-Ecb") == SQLITE_OK);
	MUST(sqlcipher_fl_set_cipher(AES_192_ECB, "aes-192-ECB") == SQLITE_OK);
	MUST(sqlcipher_fl_set_cipher(AES_256_ECB, "AES-256-ecb") == SQLITE_OK);
	/* set_cipher succeeds for invalid cipher, but name is ot set. */
	MUST(sqlcipher_fl_set_cipher(AES_CBC, "aes-512-xcb") == SQLITE_OK);
	MUST(sqlcipher_fl_get_cipher(AES_CBC) == NULL);
	MUST(sqlcipher_fl_set_cipher(AES_CBC, "aes-256-cbc") == SQLITE_OK);

	/* sqlcipher_fl_get_cipher testing */
	MUST(!strcmp(sqlcipher_fl_get_cipher(AES_128_CBC), "AES-128-CBC"));
	MUST(!strcmp(sqlcipher_fl_get_cipher(AES_192_CBC), "AES-192-CBC"));
	MUST(!strcmp(sqlcipher_fl_get_cipher(AES_256_CBC), "AES-256-CBC"));
	MUST(!strcmp(sqlcipher_fl_get_cipher(AES_128_ECB), "AES-128-ECB"));
	MUST(!strcmp(sqlcipher_fl_get_cipher(AES_192_ECB), "AES-192-ECB"));
	MUST(!strcmp(sqlcipher_fl_get_cipher(AES_256_ECB), "AES-256-ECB"));
	MUST(!strcmp(sqlcipher_fl_get_cipher(AES_CBC), "AES-256-CBC"));

	/* test sqlcipher_fl_get_key_sz */
	MUST(sqlcipher_fl_get_key_sz(AES_128_CBC) == 16);
	MUST(sqlcipher_fl_get_key_sz(AES_192_CBC) == 24);
	MUST(sqlcipher_fl_get_key_sz(AES_256_CBC) == 32);
	MUST(sqlcipher_fl_get_key_sz(AES_128_ECB) == 16);
	MUST(sqlcipher_fl_get_key_sz(AES_192_ECB) == 24);
	MUST(sqlcipher_fl_get_key_sz(AES_256_ECB) == 32);

	/* test sqlcipher_fl_get_iv_sz */
	MUST(sqlcipher_fl_get_iv_sz(AES_128_CBC) == 16);
	MUST(sqlcipher_fl_get_iv_sz(AES_192_CBC) == 16);
	MUST(sqlcipher_fl_get_iv_sz(AES_256_CBC) == 16);
	MUST(sqlcipher_fl_get_iv_sz(AES_128_ECB) == 0);
	MUST(sqlcipher_fl_get_iv_sz(AES_192_ECB) == 0);
	MUST(sqlcipher_fl_get_iv_sz(AES_256_ECB) == 0);

	/* test sqlcipher_fl_get_block_sz */
	MUST(sqlcipher_fl_get_block_sz(AES_128_CBC) == 16);
	MUST(sqlcipher_fl_get_block_sz(AES_192_CBC) == 16);
	MUST(sqlcipher_fl_get_block_sz(AES_256_CBC) == 16);
	MUST(sqlcipher_fl_get_block_sz(AES_128_ECB) == 16);
	MUST(sqlcipher_fl_get_block_sz(AES_192_ECB) == 16);
	MUST(sqlcipher_fl_get_block_sz(AES_256_ECB) == 16);

	/* test sqlcipher_fl_ctx_cmp */
	MUST(sqlcipher_fl_ctx_cmp(AES_128_CBC, AES_CBC) == 0);
	MUST(sqlcipher_fl_ctx_cmp(AES_192_CBC, AES_CBC) == 0);
	MUST(sqlcipher_fl_ctx_cmp(AES_256_CBC, AES_CBC) == 1);
	MUST(sqlcipher_fl_ctx_cmp(AES_128_ECB, AES_CBC) == 0);
	MUST(sqlcipher_fl_ctx_cmp(AES_192_ECB, AES_CBC) == 0);
	MUST(sqlcipher_fl_ctx_cmp(AES_256_ECB, AES_CBC) == 0);

	/* test sqlcipher_fl_ctx_copy (temporarily modifies AES_CBC) */
	MUST(sqlcipher_fl_ctx_copy(AES_CBC, AES_128_CBC) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_cmp(AES_128_CBC, AES_CBC) == 1);
	MUST(sqlcipher_fl_ctx_cmp(AES_256_CBC, AES_CBC) == 0);
	MUST(sqlcipher_fl_ctx_copy(AES_CBC, AES_256_CBC) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_cmp(AES_128_CBC, AES_CBC) == 0);
	MUST(sqlcipher_fl_ctx_cmp(AES_256_CBC, AES_CBC) == 1);

	/* test sqlcipher_fl_get_hmac_sz */
	MUST(sqlcipher_fl_get_hmac_sz(AES_128_CBC) == 20);
	MUST(sqlcipher_fl_get_hmac_sz(AES_192_CBC) == 20);
	MUST(sqlcipher_fl_get_hmac_sz(AES_256_CBC) == 20);
	MUST(sqlcipher_fl_get_hmac_sz(AES_128_ECB) == 20);
	MUST(sqlcipher_fl_get_hmac_sz(AES_192_ECB) == 20);
	MUST(sqlcipher_fl_get_hmac_sz(AES_256_ECB) == 20);
	MUST(sqlcipher_fl_get_hmac_sz(NULL) == 20); /* The ctx is ignored. */

	/* sqlcipher_fl_get_provider_name testing */
	MUST(!strcmp(sqlcipher_fl_get_provider_name(NULL), "fl"));
	MUST(sqlcipher_fl_get_provider_name(NULL) ==
	     sqlcipher_fl_get_provider_name(AES_CBC));

	/* sqlcipher_fl_random testing (uses NULL context, because
	   sqlcipher_fl_random ignores the context). Generates random
	   numbers which are 32 bytes long. Only checks that the RNG
	   is able to generate non-zero bytes for each byte location.
	   In case sqlcipher_fl_random generates less bytes than requested,
	   infinite loop will result.
	   Note: Typically this test will call sqlcipher_fl_random 1-2 times,
	   but more calls can be performed occasionally. */
	for (i = 0; i < (int)sizeof(tmp_data); i++) {
		if (tmp_data[i] != 0)
			continue;

		MUST(sqlcipher_fl_random(NULL, tmp_data,
					 (int)sizeof(tmp_data)) == SQLITE_OK);
	}

	/* sqlcipher_fl_add_random testing: just provide static string.
	   (uses NULL context, because sqlcipher_fl_add_random ignores the
	   context). */
	MUST(sqlcipher_fl_add_random(NULL,
				     (unsigned char *)"entropy",
				     7) == SQLITE_OK);

	/* test sqlcipher_fl_hmac (using AES-CBC's context). */
	MUST(sqlcipher_fl_hmac(AES_CBC,
			       (unsigned char *)"0123456789ABCDEF", 16,
			       (unsigned char *)"abc", 3,
			       NULL, 0,
			       tmp_data) == SQLITE_OK);

	MUST(!memcmp(tmp_data, hmac_kat, sizeof(hmac_kat)));

	/* test sqlcipher_fl_cipher
	   (using previously generated test vectors.)
	   These vectors intentionally only use printable characters, to
	   allow compact presentation of the vectors in source code. */
	MUST(sqlcipher_fl_cipher(AES_128_ECB, 0,
				 (unsigned char *)"0000008621604305", 16,
				 NULL,
				 (unsigned char *)"UGKKqU14U4arY8up", 16,
				 tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, "EXTRATERRESTRIAL", 16));
	MUST(sqlcipher_fl_cipher(AES_128_ECB, 1,
				 (unsigned char *)"0000008621604305", 16,
				 NULL,
				 tmp_data, 16,
				 tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, "UGKKqU14U4arY8up", 16));
	MUST(sqlcipher_fl_cipher(
		     AES_192_ECB, 0,
		     (unsigned char *)"000000003000000094382186", 24,
		     NULL,
		     (unsigned char *)"N2t2HL4wXPx0Esli", 16,
		     tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, "CRYOPRESERVATION", 16));
	MUST(sqlcipher_fl_cipher(
		     AES_192_ECB, 1,
		     (unsigned char *)"000000003000000094382186", 24,
		     NULL,
		     tmp_data, 16,
		     tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, "N2t2HL4wXPx0Esli", 16));
	MUST(sqlcipher_fl_cipher(
		     AES_256_ECB, 0,
		     (unsigned char *)"00000000000000005000003561554795", 32,
		     NULL,
		     (unsigned char *)"EFAl3EUq34eAzqKn", 16,
		     tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, "NONDETERMINISTIC", 16));
	MUST(sqlcipher_fl_cipher(
		     AES_256_ECB, 1,
		     (unsigned char *)"00000000000000005000003561554795", 32,
		     NULL,
		     tmp_data, 16,
		     tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, "EFAl3EUq34eAzqKn", 16));

	MUST(sqlcipher_fl_cipher(AES_128_CBC, 0,
				 (unsigned char *)"DECENTRALIZATION", 16,
				 (unsigned char *)"8000001416818244",
				 (unsigned char *)"GolJghKwWCLePGPL", 16,
				 tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, "PREDETERMINATION", 16));
	MUST(sqlcipher_fl_cipher(AES_128_CBC, 1,
				 (unsigned char *)"DECENTRALIZATION", 16,
				 (unsigned char *)"8000001416818244",
				 tmp_data, 16,
				 tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, "GolJghKwWCLePGPL", 16));
	MUST(sqlcipher_fl_cipher(
		     AES_192_CBC, 0,
		     (unsigned char *)"Llanfairpwllgwyngyllgoge", 24,
		     (unsigned char *)"9000001946007356",
		     (unsigned char *)"tJEZqOPtHdmIURlw", 16,
		     tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, "QUINTESSENTIALLY", 16));
	MUST(sqlcipher_fl_cipher(
		     AES_192_CBC, 1,
		     (unsigned char *)"Llanfairpwllgwyngyllgoge", 24,
		     (unsigned char *)"9000001946007356",
		     tmp_data, 16,
		     tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, "tJEZqOPtHdmIURlw", 16));
	MUST(sqlcipher_fl_cipher(
		     AES_256_CBC, 0,
		     (unsigned char *)"Llanfairpwllgwyngyllgogerychwyrn", 32,
		     (unsigned char *)"4000006045190858",
		     (unsigned char *)"bzbDP9CFnEz8p5JW", 16,
		     tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, "CRYPTOZOOLOGISTS", 16));
	MUST(sqlcipher_fl_cipher(
		     AES_256_CBC, 1,
		     (unsigned char *)"Llanfairpwllgwyngyllgogerychwyrn", 32,
		     (unsigned char *)"4000006045190858",
		     tmp_data, 16,
		     tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, "bzbDP9CFnEz8p5JW", 16));

	/* test sqlcipher_fl_kdf with workfactor=1000, 256 bit output  */
	MUST(sqlcipher_fl_kdf(NULL,
			      (unsigned char *)"Rosebud", 7,
			      (unsigned char *)"saltSALTsaltSALT", 16,
			      1000,
			      sizeof(kdf_kat), tmp_data) == SQLITE_OK);
	MUST(!memcmp(tmp_data, kdf_kat, sizeof(kdf_kat)));

	/* Test common error conditions (e.g. too long key) */
	MUST(sqlcipher_fl_hmac(AES_CBC,
			       (unsigned char *)"0123456789ABCDEF",
			       SQLCIPHER_FL_MAX_KEY_LEN + 1,
			       (unsigned char *)"abc", 3,
			       NULL, 0,
			       tmp_data) == SQLITE_ERROR);
	MUST(sqlcipher_fl_cipher(AES_128_ECB, 0,
				 (unsigned char *)"0000008621604305",
				 SQLCIPHER_FL_MAX_KEY_LEN + 1,
				 NULL,
				 (unsigned char *)"UGKKqU14U4arY8up", 16,
				 tmp_data) == SQLITE_ERROR);

	/* test sqlcipher_fl_ctx_free (these are the last tests as the
	   contexts are no longer usable after free). */
	MUST(sqlcipher_fl_ctx_free(&AES_128_CBC) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_free(&AES_192_CBC) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_free(&AES_256_CBC) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_free(&AES_128_ECB) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_free(&AES_192_ECB) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_free(&AES_256_ECB) == SQLITE_OK);
	MUST(sqlcipher_fl_ctx_free(&AES_CBC) == SQLITE_OK);

	/* Ensure there is no memory leaks. */
	SQLCIPHER_FL_INT_NO_MEM_ALLOCATED();
	MUST(fl_init_count == 0);
	SQLCIPHER_FL_ASSETS_ENSURE_MAX(1); /* Only the global state asset
					      allowed to remain. */
}

#ifdef SQLCIPHER_FL_MAIN
static void sqlcipher_fl_selftest_extra(void)
{
#define MORE_THAN_ASSETS 65537 /* Assume less than 65537 assets. */
	FL_AnyAsset_t assets[MORE_THAN_ASSETS];
	int i;
	int num_assets;
	unsigned char tmp_data[32] = { 0 };
	const unsigned char keydata[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	const unsigned char kdf_kat[] = {
		0xd4, 0xc2, 0xb2, 0x64, 0xd9, 0x9c, 0x58, 0x33, 0xed, 0x83,
		0x30, 0xc0, 0xaa, 0xb0, 0x4b, 0xd0, 0x91, 0x7a, 0xf3, 0x9f,
		0x86, 0xea, 0x86, 0x2f, 0x60, 0xb6, 0xdc, 0x06, 0x27, 0xb8,
		0xa2, 0xd7
	};
	/* Extra tests which are rarely useful and consume more time or
	   memory. These tests are not included in the standard power-up
	   selftest. */

	/* Ensure FIPSLib is usable */
	MUST(sqlcipher_fl_int_init() == SQLITE_OK);
	/* Ensure FIPSLib multi-init is supported. */
	MUST(sqlcipher_fl_int_init() == SQLITE_OK);

	/* These tests depend on file system contents. */
#ifdef SQLCIPHER_FL_USE_DEV_URANDOM
	MUST(sqlcipher_fl_int_FileInputConditionalTest(
		     NULL, 0, NULL) == 0);
	/* Ensure no entropy is returned if opening entropy file fails or
           wrong kind of file is opened. */
	do {
		FL_Data_t EntropyOut[1024 / 8];
		FL_DataLen_t InputSize = 1024 / 8;
		FL_DataLen_t EntropySize = 256;

		sqlcipher_fl_int_entropy_input_from("./.file_not_exists.",
						    EntropyOut,
						    1024 / 8,
						    &InputSize,
						    &EntropySize);
		MUST(InputSize == 0);
		MUST(EntropySize == 0);
	} while(0);
	do {
		FL_Data_t EntropyOut[1024 / 8];
		FL_DataLen_t InputSize = 1024 / 8;
		FL_DataLen_t EntropySize = 256;

		sqlcipher_fl_int_entropy_input_from(".",
						    EntropyOut,
						    1024 / 8,
						    &InputSize,
						    &EntropySize);
		MUST(InputSize == 0);
		MUST(EntropySize == 0);
	} while(0);
#endif /* SQLCIPHER_FL_USE_DEV_URANDOM */

	/* Try some invalid cases for sqlcipher_fl_int_new_key. */
	(void)sqlcipher_fl_int_process();
	MUST(sqlcipher_fl_int_new_key(
		     (unsigned char *) "0123456789abcdef", 16, 32,
		     FL_POLICY_ALGO_HASH_SHA1 |
		     FL_POLICY_ALGO_MAC_GENERATE) == FL_ASSET_INVALID);
	MUST(sqlcipher_fl_int_new_key(
		     NULL, ~(size_t)0, ~(size_t)0,
		     FL_POLICY_ALGO_HASH_SHA1 |
		     FL_POLICY_ALGO_MAC_GENERATE) == FL_ASSET_INVALID);
	MUST(sqlcipher_fl_int_new_key(
		     NULL, 16, 16,
		     ~(FL_PolicyFullBits_t)0) == FL_ASSET_INVALID);
	sqlcipher_fl_int_done();
	MUST(sqlcipher_fl_int_map_key(
		     (unsigned char *)"", ~(uint32_t)0,
		     FL_POLICY_ALGO_HASH_SHA1 |
		     FL_POLICY_ALGO_MAC_GENERATE) == FL_ASSET_INVALID);
	MUST(sqlcipher_fl_int_map_key(
		     (unsigned char *)"0123456789ABCDEF", 16,
		     ~(FL_PolicySmallBits_t)0) == FL_ASSET_INVALID);

	/* Check sqlcipher_fl_int_aes_unwrap function in exception
	   situations. */
	MUST(sqlcipher_fl_int_aes_unwrap(FL_ASSET_INVALID, FL_ASSET_INVALID,
					 NULL, 0) == FLR_INVALID_ARGUMENTS);
	MUST(sqlcipher_fl_int_aes_unwrap(FL_ASSET_INVALID, FL_ASSET_INVALID,
					 NULL, 63) == FLR_INVALID_ARGUMENTS);

	(void)sqlcipher_fl_int_process();
	for(i = 0; i < MORE_THAN_ASSETS; i++)
	{
		assets[i] = sqlcipher_fl_int_new_key(
			keydata, 16, 16,
			FL_POLICY_ALGO_HASH_SHA1 |
			FL_POLICY_FLAG_EXPORTABLE |
			FL_POLICY_ALGO_MAC_GENERATE);
		if (assets[i] == FL_ASSET_INVALID)
			break;
	}
	MUST(i != 0); /* Some assets are allocated. */
	MUST(i != MORE_THAN_ASSETS); /* The table is not full. */
	num_assets = i;

	/* Try export. It shall fail as there is no space for temporary asset.*/
	MUST(sqlcipher_fl_int_export(NULL, assets[0], tmp_data) != FLR_OK);

	sqlcipher_fl_int_done();

	/* Try kdf. It shall fail as there is no space for temporary asset. */
	MUST(sqlcipher_fl_kdf(NULL,
			      (unsigned char *)"Rosebud", 7,
			      (unsigned char *)"saltSALTsaltSALT", 16,
			      1000,
			      sizeof(kdf_kat), tmp_data) == SQLITE_ERROR);

	/* Free all allocated assets. */
	for(i = 0; i < num_assets; i++)
	{
		(void)FL_AssetFree(assets[i]);
		SQLCIPHER_FL_ASSETS_FREED(1);
	}

	/* Ensure there are no memory leaks. */
	SQLCIPHER_FL_INT_NO_MEM_ALLOCATED();
	MUST(fl_init_count == 0);
	SQLCIPHER_FL_ASSETS_ENSURE_MAX(1); /* Only the global state asset
					      allowed to remain. */
}
#endif /* SQLCIPHER_FL_MAIN */

#undef MUST

#endif /* SQLCIPHER_FL_SELFTEST */

#ifndef SQLCIPHER_FL_MAIN
/* Fill-in sqlcipher_provider as appropriate for using SafeZone FIPS Lib
   as the cryptographic library for SQLCipher. */
int sqlcipher_fl_setup(sqlcipher_provider *p)
{
	int res;

#ifdef SQLCIPHER_FL_SELFTEST
	/* Optional selftesting. */
	sqlcipher_fl_selftest();
#endif /* SQLCIPHER_FL_SELFTEST */

	/* Initialize. */
	res = sqlcipher_fl_int_init();
	if (res == SQLITE_OK) {
		/* Return pointers to the functions. */
		p->activate = sqlcipher_fl_activate;
		p->deactivate = sqlcipher_fl_deactivate;
		p->get_provider_name = sqlcipher_fl_get_provider_name;
		p->random = sqlcipher_fl_random;
		p->hmac = sqlcipher_fl_hmac;
		p->kdf = sqlcipher_fl_kdf;
		p->cipher = sqlcipher_fl_cipher;
		p->set_cipher = sqlcipher_fl_set_cipher;
		p->get_cipher = sqlcipher_fl_get_cipher;
		p->get_key_sz = sqlcipher_fl_get_key_sz;
		p->get_iv_sz = sqlcipher_fl_get_iv_sz;
		p->get_block_sz = sqlcipher_fl_get_block_sz;
		p->get_hmac_sz = sqlcipher_fl_get_hmac_sz;
		p->ctx_copy = sqlcipher_fl_ctx_copy;
		p->ctx_cmp = sqlcipher_fl_ctx_cmp;
		p->ctx_init = sqlcipher_fl_ctx_init;
		p->ctx_free = sqlcipher_fl_ctx_free;
		p->add_random = sqlcipher_fl_add_random;
	}

	return SQLITE_OK;
}
#endif /* SQLCIPHER_FL_MAIN */

#endif
#endif
/* END SQLCIPHER */

#ifdef SQLCIPHER_FL_MAIN
/* Simple main function for testing. This main function runs the
   selftests for purpose of determining the test coverage of the tests. */
int main(int argc, char *argv[])
{
	if (argc > 1)
		if (!strcmp(argv[1], "--verbose")) {
			fl_dbg = 1;
		} else if (!strcmp(argv[1], "--extra")) {
			sqlcipher_fl_selftest_extra();
			exit(0);
		} else if (!strcmp(argv[1], "--must-coverage")) {
			/* Enforce "MUST" to fail.
			   (To ensure MUST failure is processed correctly.) */
			must_internal((1 == 0),
				      "INTENTIONAL FAIL: func=%s: %s\n",
				      __func__, "1 == 0");
		} else {
			fprintf(stderr,
				"Usage: %s "
				"[--verbose | --extra | --must-coverage]\n",
				argv[0]);
			exit(1);
		}
#ifdef SQLCIPHER_FL_SELFTEST
	sqlcipher_fl_selftest();
#endif /* SQLCIPHER_FL_SELFTEST */
	return 0;
}
#endif /* SQLCIPHER_FL_MAIN */

/* end of file crypto_fl.c */
