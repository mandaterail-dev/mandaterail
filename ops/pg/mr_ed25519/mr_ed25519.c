/*
 * mr_ed25519: one function, mr_crypto.mr_ed25519_verify(msg bytea, sig bytea, pk bytea) -> bool.
 * Pure Ed25519 (RFC 8032) via libsodium crypto_sign_verify_detached, statically linked.
 * Wrong sizes raise (never return false): sig exactly 64 bytes, pk exactly 32, msg <= 4096.
 * docs/ops/attested-release-signer.md §3.1 (rev 9). No key material, no state.
 */
#include "postgres.h"
#include "fmgr.h"
#include "varatt.h"
#include <sodium.h>

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(mr_ed25519_verify);

void _PG_init(void);
void
_PG_init(void)
{
	if (sodium_init() < 0)
		ereport(ERROR, (errmsg("mr_ed25519: sodium_init failed")));
}

Datum
mr_ed25519_verify(PG_FUNCTION_ARGS)
{
	bytea	   *msg = PG_GETARG_BYTEA_PP(0);
	bytea	   *sig = PG_GETARG_BYTEA_PP(1);
	bytea	   *pk = PG_GETARG_BYTEA_PP(2);
	size_t		msg_len = VARSIZE_ANY_EXHDR(msg);
	size_t		sig_len = VARSIZE_ANY_EXHDR(sig);
	size_t		pk_len = VARSIZE_ANY_EXHDR(pk);

	if (sig_len != crypto_sign_BYTES)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						errmsg("mr_ed25519_verify: signature must be exactly 64 bytes (got %zu)", sig_len)));
	if (pk_len != crypto_sign_PUBLICKEYBYTES)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						errmsg("mr_ed25519_verify: public key must be exactly 32 bytes (got %zu)", pk_len)));
	if (msg_len > 4096)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						errmsg("mr_ed25519_verify: message longer than 4096 bytes")));

	PG_RETURN_BOOL(crypto_sign_verify_detached((const unsigned char *) VARDATA_ANY(sig),
											   (const unsigned char *) VARDATA_ANY(msg),
											   (unsigned long long) msg_len,
											   (const unsigned char *) VARDATA_ANY(pk)) == 0);
}
