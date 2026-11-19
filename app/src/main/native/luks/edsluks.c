/*
 * EDS LUKS2 native crypto: Argon2 KDF and AES-XTS (plain64 IV) sector decryption.
 * Copyright (C) 2026 EDS Lite contributors. GPLv2+.
 *
 * Java side: com.sovworks.eds.luks2.Luks2Native
 *
 * Key handling: XTS keys are expanded into AES key schedules held in native
 * memory and referenced by an opaque handle; freeing the handle wipes them.
 * Argon2 runs here because LUKS2 defaults use up to 1 GiB, which does not fit
 * in an Android Java heap.
 *
 * READ-ONLY: only decryption is exposed. (Encryption will be added together
 * with the write path, behind the filesystem layer.)
 *
 * NOTE: Gladman AES is table-based (not constant-time). Fine for a phone
 * holding its own keys against remote attackers; a local cache-timing
 * attacker could do better. TODO: ARMv8 Crypto Extensions path for arm64.
 */
#include <errno.h>
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "argon2.h"

typedef struct {
	aes_encrypt_ctx tweak;   /* key2: encrypts the IV */
	aes_decrypt_ctx data;    /* key1: decrypts data   */
} xts_ctx;

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;
	while (n--)
		*v++ = 0;
}

static void gf_mulx(uint8_t t[16])
{
	uint8_t carry = 0;
	for (int i = 0; i < 16; i++) {
		uint8_t c = t[i] >> 7;
		t[i] = (uint8_t)((t[i] << 1) | carry);
		carry = c;
	}
	if (carry)
		t[0] ^= 0x87;
}

/* Decrypts len bytes (multiple of sector_size) in place. IV of the first
 * sector is iv0 (plain64, little-endian), +1 per sector. */
static int xts_decrypt(const xts_ctx *x, uint8_t *buf, size_t len, uint32_t sector_size, uint64_t iv0)
{
	if (sector_size < 16 || sector_size % 16 || len % sector_size)
		return EINVAL;
	for (size_t off = 0; off < len; off += sector_size, iv0++) {
		uint8_t t[16] = {0};
		for (int i = 0; i < 8; i++)
			t[i] = (uint8_t)(iv0 >> (8 * i));
		aes_encrypt(t, t, &x->tweak);
		for (uint32_t b = 0; b < sector_size; b += 16) {
			uint8_t *p = buf + off + b;
			for (int i = 0; i < 16; i++) p[i] ^= t[i];
			aes_decrypt(p, p, &x->data);
			for (int i = 0; i < 16; i++) p[i] ^= t[i];
			gf_mulx(t);
		}
		wipe(t, sizeof t);
	}
	return 0;
}

static xts_ctx *xts_new(const uint8_t *key, size_t keylen)
{
	if (keylen != 32 && keylen != 64)
		return NULL;
	xts_ctx *x = calloc(1, sizeof(*x));
	if (!x)
		return NULL;
	int half = (int)keylen / 2;
	if (aes_decrypt_key(key, half, &x->data) != EXIT_SUCCESS ||
	    aes_encrypt_key(key + half, half, &x->tweak) != EXIT_SUCCESS) {
		wipe(x, sizeof(*x));
		free(x);
		return NULL;
	}
	return x;
}

static void xts_free(xts_ctx *x)
{
	if (x) {
		wipe(x, sizeof(*x));
		free(x);
	}
}

/* ------------------------------------------------------------------ JNI */

#define JFN(name) Java_com_sovworks_eds_luks2_Luks2Native_##name

static jbyte *get_bytes(JNIEnv *env, jbyteArray a, jsize *len)
{
	*len = (*env)->GetArrayLength(env, a);
	return (*env)->GetByteArrayElements(env, a, NULL);
}

static void release_wiped(JNIEnv *env, jbyteArray a, jbyte *p, jsize len)
{
	/* Wipe our copy (if the VM made one) and don't copy it back. */
	wipe(p, (size_t)len);
	(*env)->ReleaseByteArrayElements(env, a, p, JNI_ABORT);
}

JNIEXPORT jint JNICALL JFN(getVersion)(JNIEnv *env, jclass cls)
{
	(void)env; (void)cls;
	return 1;
}

/* type: 1 = argon2i, 2 = argon2id. Returns 0 or an ARGON2_* error code (<0). */
JNIEXPORT jint JNICALL JFN(argon2)(JNIEnv *env, jclass cls, jint type, jbyteArray pw, jbyteArray salt,
				   jint t, jint mKiB, jint lanes, jbyteArray out)
{
	(void)cls;
	jsize pl, sl, ol;
	jbyte *p = get_bytes(env, pw, &pl);
	jbyte *s = get_bytes(env, salt, &sl);
	ol = (*env)->GetArrayLength(env, out);
	uint8_t *o = malloc((size_t)ol);
	int r = ARGON2_MEMORY_ALLOCATION_ERROR;
	if (p && s && o) {
		argon2_context c;
		memset(&c, 0, sizeof c);
		c.out = o; c.outlen = (uint32_t)ol;
		c.pwd = (uint8_t *)p; c.pwdlen = (uint32_t)pl;
		c.salt = (uint8_t *)s; c.saltlen = (uint32_t)sl;
		c.t_cost = (uint32_t)t; c.m_cost = (uint32_t)mKiB;
		c.lanes = (uint32_t)lanes; c.threads = (uint32_t)lanes;
		c.version = ARGON2_VERSION_13;
		c.flags = ARGON2_DEFAULT_FLAGS; /* argon2 wipes its memory blocks itself */
		r = argon2_ctx(&c, type == 1 ? Argon2_i : Argon2_id);
		if (r == ARGON2_OK)
			(*env)->SetByteArrayRegion(env, out, 0, ol, (jbyte *)o);
	}
	if (o) { wipe(o, (size_t)ol); free(o); }
	if (p) release_wiped(env, pw, p, pl);
	if (s) (*env)->ReleaseByteArrayElements(env, salt, s, JNI_ABORT);
	return r;
}

JNIEXPORT jstring JNICALL JFN(argon2Error)(JNIEnv *env, jclass cls, jint code)
{
	(void)cls;
	return (*env)->NewStringUTF(env, argon2_error_message(code));
}

/* Returns handle or 0. The key array is wiped by the caller. */
JNIEXPORT jlong JNICALL JFN(xtsNew)(JNIEnv *env, jclass cls, jbyteArray key)
{
	(void)cls;
	jsize kl;
	jbyte *k = get_bytes(env, key, &kl);
	if (!k)
		return 0;
	xts_ctx *x = xts_new((uint8_t *)k, (size_t)kl);
	release_wiped(env, key, k, kl);
	return (jlong)(intptr_t)x;
}

JNIEXPORT void JNICALL JFN(xtsFree)(JNIEnv *env, jclass cls, jlong h)
{
	(void)env; (void)cls;
	xts_free((xts_ctx *)(intptr_t)h);
}

/* Decrypts buf[off, off+len) in place. Returns 0 or errno. */
JNIEXPORT jint JNICALL JFN(xtsDecrypt)(JNIEnv *env, jclass cls, jlong h, jbyteArray buf, jint off, jint len,
				       jint sectorSize, jlong iv0)
{
	(void)cls;
	if (!h || off < 0 || len < 0 || off + len > (*env)->GetArrayLength(env, buf))
		return EINVAL;
	jbyte *b = (*env)->GetPrimitiveArrayCritical(env, buf, NULL);
	if (!b)
		return ENOMEM;
	int r = xts_decrypt((xts_ctx *)(intptr_t)h, (uint8_t *)b + off, (size_t)len, (uint32_t)sectorSize, (uint64_t)iv0);
	(*env)->ReleasePrimitiveArrayCritical(env, buf, b, 0);
	return r;
}
