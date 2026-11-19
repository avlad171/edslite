/*
 * JNI bridge for the EDS read-only ext2/3/4 driver.
 * Copyright (C) 2026 EDS Lite contributors. GPLv2+.
 *
 * Java side: com.sovworks.eds.fs.ext4.Ext4Native
 * Block reads are served by calling back into the Java RandomAccessIO
 * (the decrypting container stream). Calls into the volume always originate
 * from a Java thread, so the callback can use that thread's JNIEnv.
 */
#include <errno.h>
#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include "edsext4_core.h"

#define CHUNK (256 * 1024)

typedef struct {
	JavaVM *vm;
	jobject io;          /* global ref to RandomAccessIO */
	jmethodID seek;      /* void seek(long) */
	jmethodID read;      /* int read(byte[], int, int) */
	jbyteArray buf;      /* global ref, CHUNK bytes */
	edsext4_vol *vol;
} jvol;

static int java_read(void *ctx, uint64_t off, void *dst, size_t len)
{
	jvol *jv = ctx;
	JNIEnv *env;
	if ((*jv->vm)->GetEnv(jv->vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK)
		return EIO;
	(*env)->CallVoidMethod(env, jv->io, jv->seek, (jlong)off);
	if ((*env)->ExceptionCheck(env)) {
		(*env)->ExceptionClear(env);
		return EIO;
	}
	uint8_t *d = dst;
	while (len > 0) {
		jint want = len > CHUNK ? CHUNK : (jint)len;
		jint got = (*env)->CallIntMethod(env, jv->io, jv->read, jv->buf, 0, want);
		if ((*env)->ExceptionCheck(env)) {
			(*env)->ExceptionClear(env);
			return EIO;
		}
		if (got <= 0)
			return EIO;
		(*env)->GetByteArrayRegion(env, jv->buf, 0, got, (jbyte *)d);
		d += got;
		len -= (size_t)got;
	}
	return 0;
}

static char *dup_path(JNIEnv *env, jstring s)
{
	const char *u = (*env)->GetStringUTFChars(env, s, NULL);
	if (!u)
		return NULL;
	char *r = strdup(u);
	(*env)->ReleaseStringUTFChars(env, s, u);
	return r;
}

#define JFN(name) Java_com_sovworks_eds_fs_ext4_Ext4Native_##name

JNIEXPORT jint JNICALL JFN(getVersion)(JNIEnv *env, jclass cls)
{
	(void)env; (void)cls;
	return 1;
}

/* Returns handle (>0) or -errno. */
JNIEXPORT jlong JNICALL JFN(mount)(JNIEnv *env, jclass cls, jobject io, jlong size)
{
	(void)cls;
	jvol *jv = calloc(1, sizeof(*jv));
	if (!jv)
		return -ENOMEM;
	(*env)->GetJavaVM(env, &jv->vm);
	jclass c = (*env)->GetObjectClass(env, io);
	jv->seek = (*env)->GetMethodID(env, c, "seek", "(J)V");
	jv->read = (*env)->GetMethodID(env, c, "read", "([BII)I");
	if (!jv->seek || !jv->read) {
		(*env)->ExceptionClear(env);
		free(jv);
		return -EINVAL;
	}
	jv->io = (*env)->NewGlobalRef(env, io);
	jbyteArray b = (*env)->NewByteArray(env, CHUNK);
	if (!b) {
		(*env)->ExceptionClear(env);
		(*env)->DeleteGlobalRef(env, jv->io);
		free(jv);
		return -ENOMEM;
	}
	jv->buf = (*env)->NewGlobalRef(env, b);
	(*env)->DeleteLocalRef(env, b);

	int err;
	jv->vol = edsext4_mount(java_read, jv, (uint64_t)size, &err);
	if (!jv->vol) {
		(*env)->DeleteGlobalRef(env, jv->buf);
		(*env)->DeleteGlobalRef(env, jv->io);
		free(jv);
		return -(jlong)(err ? err : EIO);
	}
	return (jlong)(intptr_t)jv;
}

JNIEXPORT void JNICALL JFN(umount)(JNIEnv *env, jclass cls, jlong h)
{
	(void)cls;
	jvol *jv = (jvol *)(intptr_t)h;
	if (!jv)
		return;
	edsext4_umount(jv->vol);
	/* Clear the decrypted-data scratch buffer before releasing it. */
	jbyte zero[4096] = {0};
	for (jint o = 0; o < CHUNK; o += sizeof(zero))
		(*env)->SetByteArrayRegion(env, jv->buf, o, sizeof(zero), zero);
	(*env)->DeleteGlobalRef(env, jv->buf);
	(*env)->DeleteGlobalRef(env, jv->io);
	free(jv);
}

/* out = {type, size, mtime}. Returns 0 or errno. */
JNIEXPORT jint JNICALL JFN(stat)(JNIEnv *env, jclass cls, jlong h, jstring path, jlongArray out)
{
	(void)cls;
	jvol *jv = (jvol *)(intptr_t)h;
	char *p = dup_path(env, path);
	if (!p)
		return ENOMEM;
	edsext4_stat st;
	int r = edsext4_stat_path(jv->vol, p, &st);
	free(p);
	if (r == 0) {
		jlong v[3] = {st.type, (jlong)st.size, st.mtime};
		(*env)->SetLongArrayRegion(env, out, 0, 3, v);
	}
	return r;
}

typedef struct {
	JNIEnv *env;
	jobject list;
	jmethodID add;
} list_ctx;

static int add_name(void *ctx, const char *name, size_t nl, int type)
{
	(void)type;
	list_ctx *lc = ctx;
	JNIEnv *env = lc->env;
	/* Names on disk are raw bytes (usually UTF-8, possibly 4-byte sequences
	 * that JNI's modified UTF-8 can't take), so hand byte[] to Java to decode. */
	jbyteArray s = (*env)->NewByteArray(env, (jsize)nl);
	if (!s) {
		(*env)->ExceptionClear(env);
		return ENOMEM;
	}
	(*env)->SetByteArrayRegion(env, s, 0, (jsize)nl, (const jbyte *)name);
	(*env)->CallBooleanMethod(env, lc->list, lc->add, s);
	(*env)->DeleteLocalRef(env, s);
	if ((*env)->ExceptionCheck(env)) {
		(*env)->ExceptionClear(env);
		return EIO;
	}
	return 0;
}

/* Appends raw UTF-8 entry names (byte[]) to the java.util.Collection. Returns 0 or errno. */
JNIEXPORT jint JNICALL JFN(list)(JNIEnv *env, jclass cls, jlong h, jstring path, jobject coll)
{
	(void)cls;
	jvol *jv = (jvol *)(intptr_t)h;
	char *p = dup_path(env, path);
	if (!p)
		return ENOMEM;
	list_ctx lc = {env, coll, NULL};
	jclass c = (*env)->GetObjectClass(env, coll);
	lc.add = (*env)->GetMethodID(env, c, "add", "(Ljava/lang/Object;)Z");
	int r = lc.add ? edsext4_list(jv->vol, p, add_name, &lc) : EINVAL;
	free(p);
	return r;
}

/* Returns file handle (>0) or -errno. */
JNIEXPORT jlong JNICALL JFN(open)(JNIEnv *env, jclass cls, jlong h, jstring path)
{
	(void)cls;
	jvol *jv = (jvol *)(intptr_t)h;
	char *p = dup_path(env, path);
	if (!p)
		return -ENOMEM;
	int err;
	edsext4_file *f = edsext4_open(jv->vol, p, &err);
	free(p);
	return f ? (jlong)(intptr_t)f : -(jlong)err;
}

/* Returns bytes read, 0 at EOF, or -errno. */
JNIEXPORT jint JNICALL JFN(pread)(JNIEnv *env, jclass cls, jlong fh, jlong pos, jbyteArray buf, jint off, jint len)
{
	(void)cls;
	edsext4_file *f = (edsext4_file *)(intptr_t)fh;
	if (off < 0 || len < 0 || off + len > (*env)->GetArrayLength(env, buf) || pos < 0)
		return -EINVAL;
	if (len == 0)
		return 0;
	void *tmp = malloc((size_t)len);
	if (!tmp)
		return -ENOMEM;
	int64_t n = edsext4_pread(f, (uint64_t)pos, tmp, (size_t)len);
	if (n > 0)
		(*env)->SetByteArrayRegion(env, buf, off, (jint)n, tmp);
	memset(tmp, 0, (size_t)len); /* don't leave plaintext in the native heap */
	free(tmp);
	return (jint)n;
}

JNIEXPORT jlong JNICALL JFN(fsize)(JNIEnv *env, jclass cls, jlong fh)
{
	(void)env; (void)cls;
	return (jlong)edsext4_fsize((edsext4_file *)(intptr_t)fh);
}

JNIEXPORT void JNICALL JFN(close)(JNIEnv *env, jclass cls, jlong fh)
{
	(void)env; (void)cls;
	edsext4_close((edsext4_file *)(intptr_t)fh);
}

/* out = {total, free}. Returns 0 or errno. */
JNIEXPORT jint JNICALL JFN(space)(JNIEnv *env, jclass cls, jlong h, jlongArray out)
{
	(void)cls;
	jvol *jv = (jvol *)(intptr_t)h;
	uint64_t t = 0, f = 0;
	int r = edsext4_space(jv->vol, &t, &f);
	if (r == 0) {
		jlong v[2] = {(jlong)t, (jlong)f};
		(*env)->SetLongArrayRegion(env, out, 0, 2, v);
	}
	return r;
}
