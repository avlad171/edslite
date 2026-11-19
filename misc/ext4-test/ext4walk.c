/* Desktop test harness for the EDS read-only ext4 core.
 * Usage: ext4walk <image>   -> prints "<type> <size> <path> [md5-ish fnv64]" for every entry. */
#include "edsext4_core.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int img_read(void *ctx, uint64_t off, void *buf, size_t len)
{
	int fd = *(int *)ctx;
	ssize_t r = pread(fd, buf, len, (off_t)off);
	return r == (ssize_t)len ? 0 : EIO;
}

typedef struct { char **names; int *types; int n, cap; } list_t;
static int collect(void *ctx, const char *name, size_t nl, int type)
{
	list_t *l = ctx;
	if (l->n == l->cap) {
		l->cap = l->cap ? l->cap * 2 : 16;
		l->names = realloc(l->names, l->cap * sizeof(char *));
		l->types = realloc(l->types, l->cap * sizeof(int));
	}
	l->names[l->n] = strndup(name, nl);
	l->types[l->n++] = type;
	return 0;
}

static edsext4_vol *V;
static int walk(const char *path)
{
	list_t l = {0};
	int r = edsext4_list(V, path, collect, &l);
	if (r) { printf("ERR list %s: %d\n", path, r); return r; }
	for (int i = 0; i < l.n; i++) {
		char p[4096];
		snprintf(p, sizeof p, "%s/%s", path, l.names[i]);
		edsext4_stat st;
		r = edsext4_stat_path(V, p, &st);
		if (r) { printf("ERR stat %s: %d\n", p, r); return r; }
		if (l.types[i] & EDSEXT4_F_SYMLINK) {
			/* links are checked separately (check mode); never recurse through them */
			printf("L %c %s\n", st.type == EDSEXT4_T_DIR ? 'D' : 'F', p);
			free(l.names[i]);
			continue;
		}
		if (st.type == EDSEXT4_T_DIR) {
			printf("D %s\n", p);
			if ((r = walk(p))) return r;
		} else {
			int err; edsext4_file *f = edsext4_open(V, p, &err);
			if (!f) { printf("ERR open %s: %d\n", p, err); return err; }
			uint64_t h = 1469598103934665603ULL, pos = 0; char buf[65536]; int64_t n;
			while ((n = edsext4_pread(f, pos, buf, sizeof buf)) > 0) {
				for (int64_t k = 0; k < n; k++) { h ^= (uint8_t)buf[k]; h *= 1099511628211ULL; }
				pos += n;
			}
			if (n < 0) { printf("ERR read %s: %d\n", p, (int)-n); return (int)-n; }
			if (pos != st.size || pos != edsext4_fsize(f)) { printf("ERR size %s\n", p); return EIO; }
			printf("F %" PRIu64 " %s %016" PRIx64 "\n", st.size, p, h);
			edsext4_close(f);
		}
		free(l.names[i]);
	}
	free(l.names); free(l.types);
	return 0;
}

static const char *errname(int e)
{
	return e == ENOENT ? "ENOENT" : e == ELOOP ? "ELOOP" : e == ENOTDIR ? "ENOTDIR" : e == ENAMETOOLONG ? "ENAMETOOLONG" : "EOTHER";
}

/* check mode: for each path on stdin print "<path> F <size> <fnv64>", "<path> D <n entries>" or "<path> ERR <name>" */
static void check(void)
{
	char line[4096];
	while (fgets(line, sizeof line, stdin)) {
		line[strcspn(line, "\n")] = 0;
		edsext4_stat st;
		int r = edsext4_stat_path(V, line, &st);
		if (r) { printf("%s ERR %s\n", line, errname(r)); continue; }
		if (st.type == EDSEXT4_T_DIR) {
			list_t l = {0};
			r = edsext4_list(V, line, collect, &l);
			if (r) { printf("%s ERR %s\n", line, errname(r)); continue; }
			printf("%s D", line);
			/* sorted names, links marked with @ */
			for (int a = 0; a < l.n; a++) for (int b = a + 1; b < l.n; b++)
				if (strcmp(l.names[a], l.names[b]) > 0) { char *t = l.names[a]; l.names[a] = l.names[b]; l.names[b] = t; int u = l.types[a]; l.types[a] = l.types[b]; l.types[b] = u; }
			for (int a = 0; a < l.n; a++) { printf(" %s%s", l.names[a], (l.types[a] & EDSEXT4_F_SYMLINK) ? "@" : ""); free(l.names[a]); }
			free(l.names); free(l.types);
			printf("\n");
			continue;
		}
		int err; edsext4_file *f = edsext4_open(V, line, &err);
		if (!f) { printf("%s ERR %s\n", line, errname(err)); continue; }
		uint64_t h = 1469598103934665603ULL, pos = 0; char buf[65536]; int64_t n;
		while ((n = edsext4_pread(f, pos, buf, sizeof buf)) > 0) {
			for (int64_t k = 0; k < n; k++) { h ^= (uint8_t)buf[k]; h *= 1099511628211ULL; }
			pos += n;
		}
		edsext4_close(f);
		printf("%s F %" PRIu64 " %016" PRIx64 "\n", line, pos, h);
	}
}

int main(int argc, char **argv)
{
	int fd = open(argv[1], O_RDONLY);
	struct stat s; fstat(fd, &s);
	int err;
	V = edsext4_mount(img_read, &fd, (uint64_t)s.st_size, &err);
	if (!V) { printf("ERR mount: %d\n", err); return 1; }
	edsext4_stat st;
	if (edsext4_stat_path(V, "", &st) || st.type != EDSEXT4_T_DIR) { printf("ERR root stat\n"); return 1; }
	uint64_t t, fr; edsext4_space(V, &t, &fr);
	fprintf(stderr, "total=%" PRIu64 " free=%" PRIu64 "\n", t, fr);
	int r = argc > 2 && !strcmp(argv[2], "check") ? (check(), 0) : walk("");
	edsext4_umount(V);
	return r ? 1 : 0;
}
