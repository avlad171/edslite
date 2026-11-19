/*
 * EDS ext2/3/4 driver core (read-only), built on lwext4.
 * Copyright (C) 2026 EDS Lite contributors. GPLv2+.
 *
 * Safety model:
 *  - lwext4 is mounted with read_only=true.
 *  - Independently of that, the block device write callback always fails
 *    with EROFS, so no code path in lwext4 can modify the volume.
 *  - lwext4 keeps global state (device + mount-point tables), so every call
 *    into it is serialized by one process-wide mutex.
 *  - The volume contents are attacker-controlled input (someone can hand you
 *    a crafted container). lwext4 has not been fuzzed by us; see
 *    misc/ext4-fuzz for the harness. Treat untrusted containers accordingly.
 */
#include "edsext4_core.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ext4.h"
#include "ext4_blockdev.h"
#include "ext4_inode.h"
#include "ext4_super.h"

#define PH_BSIZE 512
#define MAX_VOLS CONFIG_EXT4_MOUNTPOINTS_COUNT
#define MP_LEN 16
#define PATH_MAX_LEN 4096

struct edsext4_vol {
	struct ext4_blockdev bd;
	struct ext4_blockdev_iface iface;
	uint8_t ph_buf[PH_BSIZE];
	edsext4_read_fn rd;
	void *ctx;
	int slot;
	char dev_name[MP_LEN];
	char mp[MP_LEN];
};

struct edsext4_file {
	edsext4_vol *v;
	ext4_file f;
};

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static edsext4_vol *g_slots[MAX_VOLS];

/* ---- block device ---- */

static int bd_open(struct ext4_blockdev *bdev) { (void)bdev; return EOK; }
static int bd_close(struct ext4_blockdev *bdev) { (void)bdev; return EOK; }

static int bd_bread(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id, uint32_t blk_cnt)
{
	edsext4_vol *v = (edsext4_vol *)bdev->bdif->p_user;
	if (blk_id >= bdev->bdif->ph_bcnt || blk_cnt > bdev->bdif->ph_bcnt - blk_id)
		return EIO;
	return v->rd(v->ctx, blk_id * PH_BSIZE, buf, (size_t)blk_cnt * PH_BSIZE);
}

static int bd_bwrite(struct ext4_blockdev *bdev, const void *buf, uint64_t blk_id, uint32_t blk_cnt)
{
	(void)bdev; (void)buf; (void)blk_id; (void)blk_cnt;
	return EROFS; /* read-only driver: never write */
}

/* ---- helpers ---- */

static int build_path(const edsext4_vol *v, const char *rel, char *out, size_t out_len)
{
	while (*rel == '/')
		rel++;
	int n = snprintf(out, out_len, "%s%s", v->mp, rel);
	if (n < 0 || (size_t)n >= out_len)
		return ENAMETOOLONG;
	/* lwext4 wants directories without a trailing '/', except the mount point itself. */
	size_t l = strlen(out);
	size_t mpl = strlen(v->mp);
	while (l > mpl && out[l - 1] == '/')
		out[--l] = 0;
	return EOK;
}

/* ---- symlink resolution ----
 *
 * lwext4's path lookup does not follow symbolic links. We resolve paths here, component by
 * component, with chroot semantics: the volume root is "/", absolute link targets start from it,
 * and ".." never goes above it. So no link can point outside the volume. Like the kernel, at most
 * MAX_SYMLINKS links are followed per lookup (ELOOP), and ".." after a followed directory link
 * goes to the parent of the link's target. Caller holds g_lock.
 */
#define MAX_SYMLINKS 40

static int resolve_path(const edsext4_vol *v, const char *rel, int follow_last, char *out, size_t out_len)
{
	char pend[PATH_MAX_LEN], full[PATH_MAX_LEN], target[PATH_MAX_LEN], np[PATH_MAX_LEN];
	size_t rl = 0, pos = 0;
	int links = 0, r;
	if (out_len == 0)
		return ENAMETOOLONG;
	out[0] = 0;
	if (strlen(rel) >= sizeof(pend))
		return ENAMETOOLONG;
	strcpy(pend, rel);
	struct ext4_sblock *sb = NULL;
	r = ext4_get_sblock(v->mp, &sb);
	if (r != EOK)
		return r;

	for (;;) {
		while (pend[pos] == '/')
			pos++;
		if (!pend[pos])
			break;
		size_t start = pos;
		while (pend[pos] && pend[pos] != '/')
			pos++;
		size_t clen = pos - start;
		const char *c = pend + start;
		if (clen == 1 && c[0] == '.')
			continue;
		if (clen == 2 && c[0] == '.' && c[1] == '.') {
			while (rl > 0 && out[rl - 1] != '/')
				rl--;
			if (rl > 0)
				rl--;
			out[rl] = 0;
			continue;
		}
		size_t prev = rl;
		if (rl + (rl ? 1 : 0) + clen + 1 > out_len)
			return ENAMETOOLONG;
		if (rl)
			out[rl++] = '/';
		memcpy(out + rl, c, clen);
		rl += clen;
		out[rl] = 0;

		size_t q = pos;
		while (pend[q] == '/')
			q++;
		int last = pend[q] == 0;
		if (last && !follow_last)
			break;

		r = build_path(v, out, full, sizeof(full));
		if (r != EOK)
			return r;
		uint32_t ino = 0;
		struct ext4_inode inode;
		r = ext4_raw_inode_fill(full, &ino, &inode);
		if (r == ENOENT && last)
			break; /* the caller reports the missing final component */
		if (r != EOK)
			return r;
		uint32_t mode = ext4_inode_get_mode(sb, &inode) & 0xF000;
		if (mode == EXT4_INODE_MODE_SOFTLINK) {
			if (++links > MAX_SYMLINKS)
				return ELOOP;
			uint64_t lsz = ext4_inode_get_size(sb, &inode);
			if (lsz == 0)
				return ENOENT;
			if (lsz >= sizeof(target))
				return ENAMETOOLONG;
			size_t n = 0;
			r = ext4_readlink(full, target, (size_t)lsz, &n);
			if (r != EOK)
				return r;
			if (n != lsz || memchr(target, 0, n))
				return EIO;
			target[n] = 0;
			int k = snprintf(np, sizeof(np), "%s/%s", target, pend + pos);
			if (k < 0 || (size_t)k >= sizeof(np))
				return ENAMETOOLONG;
			strcpy(pend, np);
			pos = 0;
			rl = target[0] == '/' ? 0 : prev; /* drop the link itself */
			out[rl] = 0;
			continue;
		}
		if (!last && mode != EXT4_INODE_MODE_DIRECTORY)
			return ENOTDIR;
	}
	return EOK;
}

/* Resolves rel (following all links) and builds the lwext4 path. Caller holds g_lock. */
static int resolved_full_path(const edsext4_vol *v, const char *rel, char *full, size_t full_len)
{
	char res[PATH_MAX_LEN];
	int r = resolve_path(v, rel, 1, res, sizeof(res));
	return r != EOK ? r : build_path(v, res, full, full_len);
}

/* ---- public API ---- */

edsext4_vol *edsext4_mount(edsext4_read_fn rd, void *ctx, uint64_t size_bytes, int *err)
{
	*err = EOK;
	if (size_bytes < 2048) {
		*err = EINVAL;
		return NULL;
	}
	edsext4_vol *v = calloc(1, sizeof(*v));
	if (!v) {
		*err = ENOMEM;
		return NULL;
	}
	v->rd = rd;
	v->ctx = ctx;
	v->iface.open = bd_open;
	v->iface.bread = bd_bread;
	v->iface.bwrite = bd_bwrite;
	v->iface.close = bd_close;
	v->iface.ph_bsize = PH_BSIZE;
	v->iface.ph_bcnt = size_bytes / PH_BSIZE;
	v->iface.ph_bbuf = v->ph_buf;
	v->iface.p_user = v;
	v->bd.bdif = &v->iface;
	v->bd.part_offset = 0;
	v->bd.part_size = v->iface.ph_bcnt * PH_BSIZE;

	pthread_mutex_lock(&g_lock);
	int slot = -1;
	for (int i = 0; i < MAX_VOLS; i++)
		if (!g_slots[i]) {
			slot = i;
			break;
		}
	if (slot < 0) {
		pthread_mutex_unlock(&g_lock);
		free(v);
		*err = EMFILE;
		return NULL;
	}
	v->slot = slot;
	snprintf(v->dev_name, sizeof(v->dev_name), "edsdev%d", slot);
	snprintf(v->mp, sizeof(v->mp), "/eds%d/", slot);

	int r = ext4_device_register(&v->bd, v->dev_name);
	if (r == EOK) {
		r = ext4_mount(v->dev_name, v->mp, true);
		if (r != EOK)
			ext4_device_unregister(v->dev_name);
	}
	if (r == EOK)
		g_slots[slot] = v;
	pthread_mutex_unlock(&g_lock);

	if (r != EOK) {
		free(v);
		*err = r;
		return NULL;
	}
	return v;
}

void edsext4_umount(edsext4_vol *v)
{
	if (!v)
		return;
	pthread_mutex_lock(&g_lock);
	ext4_umount(v->mp);
	ext4_device_unregister(v->dev_name);
	g_slots[v->slot] = NULL;
	pthread_mutex_unlock(&g_lock);
	free(v);
}

static int stat_locked(edsext4_vol *v, const char *path, edsext4_stat *st)
{
	char p[PATH_MAX_LEN];
	int r = resolved_full_path(v, path, p, sizeof(p));
	if (r != EOK)
		return r;
	struct ext4_sblock *sb = NULL;
	struct ext4_inode inode;
	uint32_t ino = 0;
	r = ext4_get_sblock(v->mp, &sb);
	if (r == EOK)
		r = ext4_raw_inode_fill(p, &ino, &inode);
	if (r == EOK) {
		uint32_t mode = ext4_inode_get_mode(sb, &inode) & 0xF000;
		st->type = mode == EXT4_INODE_MODE_DIRECTORY ? EDSEXT4_T_DIR
			 : mode == EXT4_INODE_MODE_FILE    ? EDSEXT4_T_FILE
							   : EDSEXT4_T_OTHER;
		st->size = ext4_inode_get_size(sb, &inode);
		st->mtime = (int64_t)ext4_inode_get_modif_time(&inode);
	}
	return r;
}

int edsext4_stat_path(edsext4_vol *v, const char *path, edsext4_stat *st)
{
	pthread_mutex_lock(&g_lock);
	int r = stat_locked(v, path, st);
	pthread_mutex_unlock(&g_lock);
	return r;
}

int edsext4_list(edsext4_vol *v, const char *path, edsext4_dirent_cb cb, void *ctx)
{
	char p[PATH_MAX_LEN];
	ext4_dir d;
	char **links = NULL;
	size_t nlinks = 0, cap = 0;
	pthread_mutex_lock(&g_lock);
	int r = resolved_full_path(v, path, p, sizeof(p));
	if (r == EOK)
		r = ext4_dir_open(&d, p);
	if (r != EOK) {
		pthread_mutex_unlock(&g_lock);
		return r;
	}
	const ext4_direntry *de;
	while ((de = ext4_dir_entry_next(&d)) != NULL) {
		size_t nl = de->name_length;
		if ((nl == 1 && de->name[0] == '.') ||
		    (nl == 2 && de->name[0] == '.' && de->name[1] == '.'))
			continue;
		if (de->inode_type == EXT4_DE_SYMLINK) {
			/* resolved after the directory is closed (no nested lookups mid-iteration) */
			if (nlinks == cap) {
				size_t nc = cap ? cap * 2 : 16;
				char **nl2 = realloc(links, nc * sizeof(char *));
				if (!nl2) { r = ENOMEM; break; }
				links = nl2;
				cap = nc;
			}
			char *nm = malloc(nl + 1);
			if (!nm) { r = ENOMEM; break; }
			memcpy(nm, de->name, nl);
			nm[nl] = 0;
			links[nlinks++] = nm;
			continue;
		}
		int t;
		if (de->inode_type == EXT4_DE_DIR)
			t = EDSEXT4_T_DIR;
		else if (de->inode_type == EXT4_DE_REG_FILE)
			t = EDSEXT4_T_FILE;
		else
			continue; /* devices, fifos, sockets: not exposed */
		r = cb(ctx, (const char *)de->name, nl, t);
		if (r != 0)
			break;
	}
	ext4_dir_close(&d);
	/* Symlinks are listed with their target's type; broken links, loops and links to special
	 * files are left out. */
	for (size_t i = 0; i < nlinks; i++) {
		if (r == 0) {
			char lp[PATH_MAX_LEN];
			int k = snprintf(lp, sizeof(lp), "%s/%s", path, links[i]);
			edsext4_stat st;
			if (k > 0 && (size_t)k < sizeof(lp) && stat_locked(v, lp, &st) == EOK && st.type != EDSEXT4_T_OTHER)
				r = cb(ctx, links[i], strlen(links[i]), st.type | EDSEXT4_F_SYMLINK);
		}
		free(links[i]);
	}
	free(links);
	pthread_mutex_unlock(&g_lock);
	return r;
}

edsext4_file *edsext4_open(edsext4_vol *v, const char *path, int *err)
{
	char p[PATH_MAX_LEN];
	edsext4_file *f = calloc(1, sizeof(*f));
	if (!f) {
		*err = ENOMEM;
		return NULL;
	}
	f->v = v;
	pthread_mutex_lock(&g_lock);
	*err = resolved_full_path(v, path, p, sizeof(p));
	if (*err == EOK)
		*err = ext4_fopen2(&f->f, p, O_RDONLY);
	pthread_mutex_unlock(&g_lock);
	if (*err != EOK) {
		free(f);
		return NULL;
	}
	return f;
}

int64_t edsext4_pread(edsext4_file *f, uint64_t pos, void *buf, size_t len)
{
	size_t rc = 0;
	pthread_mutex_lock(&g_lock);
	uint64_t sz = ext4_fsize(&f->f);
	int r = EOK;
	if (pos < sz) {
		if (len > sz - pos)
			len = (size_t)(sz - pos);
		r = ext4_fseek(&f->f, (int64_t)pos, SEEK_SET);
		if (r == EOK)
			r = ext4_fread(&f->f, buf, len, &rc);
	}
	pthread_mutex_unlock(&g_lock);
	return r == EOK ? (int64_t)rc : -(int64_t)r;
}

uint64_t edsext4_fsize(edsext4_file *f)
{
	pthread_mutex_lock(&g_lock);
	uint64_t s = ext4_fsize(&f->f);
	pthread_mutex_unlock(&g_lock);
	return s;
}

void edsext4_close(edsext4_file *f)
{
	if (!f)
		return;
	pthread_mutex_lock(&g_lock);
	ext4_fclose(&f->f);
	pthread_mutex_unlock(&g_lock);
	free(f);
}

int edsext4_space(edsext4_vol *v, uint64_t *total, uint64_t *free_bytes)
{
	struct ext4_mount_stats s;
	pthread_mutex_lock(&g_lock);
	int r = ext4_mount_point_stats(v->mp, &s);
	pthread_mutex_unlock(&g_lock);
	if (r == EOK) {
		*total = s.blocks_count * (uint64_t)s.block_size;
		*free_bytes = s.free_blocks_count * (uint64_t)s.block_size;
	}
	return r;
}
