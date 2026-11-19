package com.sovworks.eds.fs.ext4;

import com.sovworks.eds.fs.RandomAccessIO;
import com.sovworks.eds.luks2.Luks2Header;
import com.sovworks.eds.luks2.Luks2Volume;
import com.sovworks.eds.luks2.Lvm2;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Full read-only stack test: raw device -> GPT partition -> LUKS2 -> LVM2 -> ext4 (lwext4).
 * Usage: StackTest <device> <partOffset> <partSize> <passFile> [paths...]
 */
public class StackTest
{
    /** GPT partition window over the raw device (macOS raw devices need 4K-aligned I/O). */
    static class Part implements Luks2Header.Source
    {
        final RandomAccessFile f; final long base, len;
        Part(RandomAccessFile f, long base, long len) { this.f = f; this.base = base; this.len = len; }
        public long size() { return len; }
        public void readFully(long off, byte[] b, int o, int l) throws IOException
        {
            if (off < 0 || off + l > len) throw new IOException("read outside partition");
            long st = (base + off) & ~4095L, en = (base + off + l + 4095) & ~4095L;
            byte[] t = new byte[(int) (en - st)];
            synchronized (f) { f.seek(st); f.readFully(t); }
            System.arraycopy(t, (int) (base + off - st), b, o, l);
        }
    }

    /** Read-only RandomAccessIO over a Source; every write method throws. */
    static class SourceIO implements RandomAccessIO
    {
        final Luks2Header.Source s; long pos;
        SourceIO(Luks2Header.Source s) { this.s = s; }
        public int read() throws IOException { byte[] b = new byte[1]; return read(b, 0, 1) == 1 ? b[0] & 0xff : -1; }
        public int read(byte[] b, int o, int l) throws IOException
        {
            long n = Math.min(l, s.size() - pos);
            if (n <= 0) return -1;
            s.readFully(pos, b, o, (int) n); pos += n; return (int) n;
        }
        public void seek(long p) { pos = p; }
        public long getFilePointer() { return pos; }
        public long length() throws IOException { return s.size(); }
        public void write(int b) throws IOException { throw new IOException("read-only"); }
        public void write(byte[] b, int o, int l) throws IOException { throw new IOException("read-only"); }
        public void flush() {}
        public void setLength(long l) throws IOException { throw new IOException("read-only"); }
        public void close() {}
    }

    public static void main(String[] a) throws Exception
    {
        try (RandomAccessFile f = new RandomAccessFile(a[0], "r"))
        {
            Part part = new Part(f, Long.parseLong(a[1]), Long.parseLong(a[2]));
            byte[] pw = Files.readAllBytes(Paths.get(a[3]));
            Luks2Header h = Luks2Header.read(part);
            try (Luks2Volume v = Luks2Volume.unlock(part, h, pw, null))
            {
                Arrays.fill(pw, (byte) 0);
                Lvm2 lvm = Lvm2.read(v);
                System.out.println("VG " + lvm.vgName + " seqno " + lvm.seqno);
                for (Lvm2.LogicalVolume lv : lvm.volumes.values())
                    System.out.printf("  LV %-12s %8.2f GB  %d segment(s)%n", lv.name, lv.size / 1e9, lv.segsCount());
                lvm.unsupported.forEach((n, why) -> System.out.println("  LV " + n + " unsupported: " + why));

                for (Lvm2.LogicalVolume lv : lvm.volumes.values())
                {
                    SourceIO io = new SourceIO(lv);
                    byte[] sb = new byte[2];
                    lv.readFully(1080, sb, 0, 2);
                    if ((sb[0] & 0xff) != 0x53 || (sb[1] & 0xff) != 0xEF)
                    {
                        System.out.println("\n[" + lv.name + "] not ext2/3/4");
                        continue;
                    }
                    long t0 = System.nanoTime();
                    long vol = Ext4Native.mount(io, lv.size);
                    if (vol <= 0) { System.out.println("\n[" + lv.name + "] mount failed: " + "errno " + (-vol) + (-vol == 45 || -vol == 95 ? " (unsupported ext4 feature)" : "")); continue; }
                    System.out.printf("%n[%s] mounted read-only in %.2fs%n", lv.name, (System.nanoTime() - t0) / 1e9);
                    long[] sp = new long[2];
                    Ext4Native.space(vol, sp);
                    System.out.printf("  %.1f GB total, %.1f GB free%n", sp[0] / 1e9, sp[1] / 1e9);
                    ls(vol, "", 1);
                    for (int i = 4; i < a.length; i++)
                        if (a[i].equals("dpkg:*"))
                        {
                            ArrayList<byte[]> names = new ArrayList<>();
                            Ext4Native.list(vol, "var/lib/dpkg/info", names);
                            for (byte[] nm : names)
                            {
                                String fn = new String(nm, StandardCharsets.UTF_8);
                                if (fn.endsWith(".md5sums")) verifyDpkg(vol, fn.substring(0, fn.length() - 8));
                            }
                            System.out.printf("  TOTAL: %d files ok, %d mismatched, %.1f MB verified%n", TOK, TBAD, TBYTES / 1e6);
                        }
                        else if (a[i].startsWith("dpkg:")) for (String pkg : a[i].substring(5).split(",")) verifyDpkg(vol, pkg);
                        else cat(vol, a[i]);
                    Ext4Native.umount(vol);
                }
            }
        }
    }

    static long TOK, TBAD, TBYTES; static boolean QUIET = Boolean.getBoolean("quiet");

    /** Verifies every file of an installed Debian package against dpkg's md5sums. */
    static void verifyDpkg(long vol, String pkg) throws Exception
    {
        String list = readAll(vol, "var/lib/dpkg/info/" + pkg + ".md5sums");
        if (list == null) { System.out.println("  dpkg " + pkg + ": no md5sums"); return; }
        int ok = 0, bad = 0, skipped = 0; long bytes = 0;
        for (String line : list.split("\n"))
        {
            if (line.isBlank()) continue;
            String want = line.substring(0, 32), path = line.substring(34);
            long[] st = new long[3];
            if (Ext4Native.stat(vol, path, st) != 0 || st[0] != Ext4Native.T_FILE) { skipped++; continue; }
            long fh = Ext4Native.open(vol, path);
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] b = new byte[1 << 20]; long pos = 0; int n;
            while ((n = Ext4Native.pread(fh, pos, b, 0, b.length)) > 0) { md.update(b, 0, n); pos += n; }
            Ext4Native.close(fh);
            if (n < 0 || pos != st[1]) { bad++; System.out.println("    READ ERROR " + path); continue; }
            bytes += pos;
            if (HexFormat.of().formatHex(md.digest()).equals(want)) ok++;
            else { bad++; System.out.println("    MISMATCH " + path); }
        }
        TOK += ok; TBAD += bad; TBYTES += bytes;
        if (bad > 0 || !QUIET) System.out.printf("  dpkg %-14s %4d ok, %d mismatched, %d skipped (diverted/removed/symlink), %.1f MB%n", pkg, ok, bad, skipped, bytes / 1e6);
    }

    static String readAll(long vol, String path)
    {
        long fh = Ext4Native.open(vol, path);
        if (fh <= 0) return null;
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        byte[] b = new byte[65536]; long pos = 0; int n;
        while ((n = Ext4Native.pread(fh, pos, b, 0, b.length)) > 0) { o.write(b, 0, n); pos += n; }
        Ext4Native.close(fh);
        return o.toString(StandardCharsets.UTF_8);
    }

    static void ls(long vol, String path, int depth) throws IOException
    {
        ArrayList<byte[]> names = new ArrayList<>();
        int r = Ext4Native.list(vol, path, names);
        if (r != 0) { System.out.println("  list " + path + " failed: " + r); return; }
        ArrayList<String> out = new ArrayList<>();
        for (byte[] n : names) out.add(new String(n, StandardCharsets.UTF_8));
        out.sort(null);
        System.out.println("  " + (path.isEmpty() ? "/" : path) + ": " + String.join(" ", out));
    }

    static void cat(long vol, String path) throws Exception
    {
        long[] st = new long[3];
        int r = Ext4Native.stat(vol, path, st);
        if (r != 0) { System.out.println("  " + path + ": stat error " + r); return; }
        if (st[0] != Ext4Native.T_FILE) { System.out.println("  " + path + ": not a regular file"); return; }
        long fh = Ext4Native.open(vol, path);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] b = new byte[1 << 20]; long pos = 0; int n; byte[] head = null;
        while ((n = Ext4Native.pread(fh, pos, b, 0, b.length)) > 0)
        {
            if (head == null) head = Arrays.copyOf(b, Math.min(n, 400));
            md.update(b, 0, n); pos += n;
        }
        Ext4Native.close(fh);
        System.out.printf("  %s: %d bytes, sha256 %s%n", path, pos, HexFormat.of().formatHex(md.digest()));
        if (head != null && path.endsWith("os-release"))
            System.out.println(new String(head, StandardCharsets.UTF_8).replaceAll("(?m)^", "    | "));
    }
}
