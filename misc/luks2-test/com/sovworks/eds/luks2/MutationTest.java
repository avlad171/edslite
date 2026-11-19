package com.sovworks.eds.luks2;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.function.Function;

/**
 * Negative tests: take an in-memory copy of a real LUKS2 header area (read-only from the device),
 * damage it in specific ways, and check the parser/unlocker behaves (falls back or refuses).
 * Usage: MutationTest <device> <partOffset> <passFile>
 */
public class MutationTest
{
    static final class Mem implements Luks2Header.Source
    {
        final byte[] d; final long size;
        Mem(byte[] d, long size) { this.d = d; this.size = size; }
        public long size() { return size; }
        public void readFully(long off, byte[] b, int o, int l) throws IOException
        {
            if (off < 0 || off + l > size) throw new IOException("read outside device");
            if (off + l > d.length) throw new IOException("test image too small");
            System.arraycopy(d, (int) off, b, o, l);
        }
    }

    static byte[] ORIG; static long HDR; static byte[] PW; static int pass, fail;

    public static void main(String[] a) throws Exception
    {
        int len = 16 << 20; // through end of keyslot area (segment starts at 16 MiB)
        ORIG = new byte[len];
        try (RandomAccessFile f = new RandomAccessFile(a[0], "r")) { f.seek(Long.parseLong(a[1])); f.readFully(ORIG); }
        PW = Files.readAllBytes(Paths.get(a[2]));
        HDR = ByteBuffer.wrap(ORIG).getLong(8);
        long dev = 247028776960L;

        expectOk("unmodified", d -> d, dev, h -> !h.copiesOutOfSync && !h.usedSecondary, true);
        expectOk("primary JSON corrupted -> secondary used", d -> { d[4096 + 10] ^= 1; return d; }, dev, h -> h.usedSecondary && h.copiesOutOfSync, true);
        expectOk("secondary corrupted -> primary used, flagged", d -> { d[(int) HDR + 4096 + 10] ^= 1; return d; }, dev, h -> !h.usedSecondary && h.copiesOutOfSync, true);
        expectOk("primary binary magic destroyed -> secondary", d -> { d[0] = 'X'; return d; }, dev, h -> h.usedSecondary, true);
        expectRefused("both copies corrupted", d -> { d[4096 + 10] ^= 1; d[(int) HDR + 4096 + 10] ^= 1; return d; }, dev, "no valid LUKS2 header");
        expectOk("primary newer seqid -> primary, out-of-sync flagged", d -> { setSeq(d, 0, 99); resign(d, 0); return d; }, dev, h -> h.seqid == 99 && h.copiesOutOfSync, true);
        expectOk("secondary newer seqid -> secondary", d -> { setSeq(d, HDR, 99); resign(d, HDR); return d; }, dev, h -> h.usedSecondary && h.seqid == 99, true);
        expectRefused("illegal hdr_size", d -> { ByteBuffer.wrap(d).putLong(8, 12345); ByteBuffer.wrap(d).putLong((int) HDR + 8, 12345); return d; }, dev, "no valid");
        expectRefused("device smaller than header", d -> d, 4096, "no valid");
        expectRefused("device ends inside data segment start", d -> d, (16 << 20) - 4096, "beyond end");

        json("re-encryption requirement", s -> s.replaceFirst("\"config\":\\{", "\"config\":{\"requirements\":{\"mandatory\":[\"online-reencrypt-v2\"]},"), "mandatory requirements");
        json("reencrypt keyslot", s -> s.replaceFirst("\"keyslots\":\\{", "\"keyslots\":{\"9\":{\"type\":\"reencrypt\",\"key_size\":1,\"area\":{\"type\":\"none\"}},"), "re-encryption keyslot");
        json("second segment (reencryption)", s -> s.replaceFirst("\"segments\":\\{", "\"segments\":{\"1\":{\"type\":\"linear\",\"offset\":\"0\",\"size\":\"512\"},"), "2 segments");
        json("segment in-reencryption flag", s -> s.replaceFirst("(\"segments\":\\{\"0\":\\{)", "$1\"flags\":[\"in-reencryption\"],"), "segment flags");
        json("dm-integrity segment", s -> s.replaceFirst("(\"segments\":\\{\"0\":\\{)", "$1\"integrity\":{\"type\":\"hmac(sha256)\"},"), "dm-integrity");
        json("segment overlaps header", s -> s.replaceFirst("(\"segments\":\\{\"0\":\\{[^}]*\"offset\":\")\\d+", "$10"), "overlaps header");
        json("keyslot area outside keyslots area", s -> s.replaceFirst("(\"area\":\\{[^}]*\"offset\":\")\\d+", "$1999999999999"), "outside keyslots area");
        json("duplicate JSON key", s -> s.replaceFirst("\"config\":\\{", "\"config\":{\"json_size\":\"1\","), "duplicate key");
        json("deep nesting", s -> s.replaceFirst("\"config\":\\{", "\"config\":{\"x\":" + "[".repeat(100) + "]".repeat(100) + ","), "nesting too deep");
        json("non-integer number", s -> s.replaceFirst("\"stripes\":4000", "\"stripes\":4000.5"), "non-integer");
        json("unknown KDF", s -> s.replaceFirst("\"argon2id\"", "\"scrypt\""), "unsupported KDF");
        json("absurd Argon2 memory", s -> s.replaceFirst("\"memory\":\\d+", "\"memory\":999999999"), "out of range");
        json("truncated JSON", s -> s.substring(0, s.length() / 2), "JSON");

        // Unlock-level failures (need native Argon2/XTS)
        Luks2Native.ensureLoaded();
        unlockExpect("wrong passphrase", ORIG.clone(), "x".getBytes(), "no keyslot matches");
        byte[] dmg = ORIG.clone();
        Luks2Header h = Luks2Header.read(new Mem(dmg, dev));
        dmg[(int) h.keyslots.get(0).areaOffset + 1000] ^= 1; // flip one bit of AF material
        unlockExpect("keyslot material bit-flip", dmg, PW, "no keyslot matches");
        unlockExpect("correct passphrase", ORIG.clone(), PW, null);

        System.out.printf("%n%d passed, %d failed%n", pass, fail);
        Arrays.fill(PW, (byte) 0);
        System.exit(fail == 0 ? 0 : 1);
    }

    interface Mut { byte[] apply(byte[] d) throws Exception; }

    static void expectOk(String name, Mut m, long dev, Function<Luks2Header, Boolean> check, boolean ignored) throws Exception
    {
        try
        {
            Luks2Header h = Luks2Header.read(new Mem(m.apply(ORIG.clone()), dev));
            report(name, check.apply(h), "secondary=" + h.usedSecondary + " outOfSync=" + h.copiesOutOfSync + " " + h.warnings);
        }
        catch (Exception e) { report(name, false, "unexpected: " + e.getMessage()); }
    }

    static void expectRefused(String name, Mut m, long dev, String msg) throws Exception
    {
        try
        {
            Luks2Header.read(new Mem(m.apply(ORIG.clone()), dev));
            report(name, false, "was accepted");
        }
        catch (Luks2Exception e) { report(name, e.getMessage().contains(msg), e.getMessage()); }
    }

    /** Edit the JSON of both copies and re-sign them, so only semantic validation can catch it. */
    static void json(String name, Function<String, String> edit, String msg) throws Exception
    {
        expectRefused(name, d -> { for (long off : new long[]{0, HDR}) setJson(d, off, edit.apply(getJson(d, off))); return d; }, 247028776960L, msg);
    }

    static String getJson(byte[] d, long off)
    {
        int s = (int) off + 4096, e = s;
        while (d[e] != 0) e++;
        return new String(d, s, e - s, StandardCharsets.UTF_8);
    }

    static void setJson(byte[] d, long off, String js) throws Exception
    {
        byte[] j = js.getBytes(StandardCharsets.UTF_8);
        if (j.length >= HDR - 4096) throw new IllegalStateException("JSON too big");
        Arrays.fill(d, (int) off + 4096, (int) (off + HDR), (byte) 0);
        System.arraycopy(j, 0, d, (int) off + 4096, j.length);
        resign(d, off);
    }

    static void setSeq(byte[] d, long off, long seq) { ByteBuffer.wrap(d).putLong((int) off + 16, seq); }

    static void resign(byte[] d, long off) throws Exception
    {
        byte[] area = Arrays.copyOfRange(d, (int) off, (int) (off + HDR));
        Arrays.fill(area, 448, 512, (byte) 0);
        byte[] c = MessageDigest.getInstance("SHA-256").digest(area);
        Arrays.fill(d, (int) off + 448, (int) off + 512, (byte) 0);
        System.arraycopy(c, 0, d, (int) off + 448, c.length);
    }

    static void unlockExpect(String name, byte[] img, byte[] pw, String msg)
    {
        Mem m = new Mem(img, 247028776960L);
        try
        {
            Luks2Header h = Luks2Header.read(m);
            try (Luks2Volume v = Luks2Volume.unlock(m, h, pw.clone(), null))
            {
                report(name, msg == null, "unlocked");
            }
        }
        catch (Exception e) { report(name, msg != null && String.valueOf(e.getMessage()).contains(msg), e.getMessage()); }
    }

    static void report(String name, boolean ok, String detail)
    {
        if (ok) pass++; else fail++;
        System.out.printf("%s %-48s %s%n", ok ? "OK  " : "FAIL", name, detail);
    }
}
