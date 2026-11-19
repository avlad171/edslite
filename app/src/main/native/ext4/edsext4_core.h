/*
 * EDS ext2/3/4 driver core (read-only), built on lwext4.
 * Copyright (C) 2026 EDS Lite contributors. GPLv2+.
 *
 * The core knows nothing about JNI. The volume is accessed through a
 * user-supplied read callback so the same code runs on Android (where the
 * callback reads from the decrypting EDS RandomAccessIO) and in the
 * desktop test harness (where it reads a plain image file).
 */
#ifndef EDSEXT4_CORE_H
#define EDSEXT4_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Reads exactly len bytes at byte offset off. Returns 0 on success, errno otherwise. */
typedef int (*edsext4_read_fn)(void *ctx, uint64_t off, void *buf, size_t len);

typedef struct edsext4_vol edsext4_vol;
typedef struct edsext4_file edsext4_file;

#define EDSEXT4_T_OTHER 0
#define EDSEXT4_T_FILE  1
#define EDSEXT4_T_DIR   2
/* OR-ed into the list callback's type for an entry that is a symbolic link (type = its target's). */
#define EDSEXT4_F_SYMLINK 0x100

typedef struct {
	int type;          /* EDSEXT4_T_* */
	uint64_t size;
	int64_t mtime;     /* seconds since epoch */
} edsext4_stat;

/* Mounts read-only. On failure returns NULL and stores errno in *err. */
edsext4_vol *edsext4_mount(edsext4_read_fn rd, void *ctx, uint64_t size_bytes, int *err);
void edsext4_umount(edsext4_vol *v);

/* Paths are relative to the volume root; "" or "/" is the root. Symbolic links are followed,
 * confined to the volume (absolute targets start at its root, ".." stops there; ELOOP after 40). */
int edsext4_stat_path(edsext4_vol *v, const char *path, edsext4_stat *st);

/* Calls cb for each regular file / directory in the directory (skips ".", "..", special files,
 * broken links and loops; links come last, typed as their target | EDSEXT4_F_SYMLINK).
 * Stops and returns cb's value if it is non-zero. */
typedef int (*edsext4_dirent_cb)(void *ctx, const char *name, size_t name_len, int type);
int edsext4_list(edsext4_vol *v, const char *path, edsext4_dirent_cb cb, void *ctx);

edsext4_file *edsext4_open(edsext4_vol *v, const char *path, int *err);
/* Returns bytes read (0 at EOF) or -errno. */
int64_t edsext4_pread(edsext4_file *f, uint64_t pos, void *buf, size_t len);
uint64_t edsext4_fsize(edsext4_file *f);
void edsext4_close(edsext4_file *f);

int edsext4_space(edsext4_vol *v, uint64_t *total, uint64_t *free_bytes);

#ifdef __cplusplus
}
#endif
#endif
