package com.sovworks.eds.luks2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * LUKS2 header reader/validator (pure Java, no Android dependencies).
 *
 * Follows the LUKS2 on-disk format spec (cryptsetup docs/on-disk-format-luks2.pdf):
 * two binary headers (primary at 0, secondary at hdr_size), each followed by a JSON area,
 * each covered by a checksum. The valid copy with the highest seqid wins.
 *
 * Anything this code does not fully understand is refused rather than guessed:
 * re-encryption in progress, dm-integrity, multiple segments, unknown mandatory
 * requirements, unknown keyslot/area/KDF/AF types, out-of-bounds or overlapping areas.
 */
public final class Luks2Header
{
    /** Random-access, read-only view of the device/partition holding the LUKS2 volume. */
    public interface Source
    {
        long size() throws IOException;
        /** Reads exactly len bytes at off or throws. */
        void readFully(long off, byte[] buf, int bufOff, int len) throws IOException;
    }

    static final byte[] MAGIC1 = {'L', 'U', 'K', 'S', (byte) 0xBA, (byte) 0xBE};
    static final byte[] MAGIC2 = {'S', 'K', 'U', 'L', (byte) 0xBA, (byte) 0xBE};
    static final int BIN_SIZE = 4096, CSUM_OFF = 448, CSUM_LEN = 64;
    static final long[] HDR_SIZES = {0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000};

    // ---------------------------------------------------------------- model

    public static final class Kdf
    {
        public String type;           // pbkdf2 | argon2i | argon2id
        public String hash;           // pbkdf2 only
        public long iterations;       // pbkdf2 only
        public long time, memoryKiB, cpus; // argon2 only
        public byte[] salt;
    }

    public static final class Keyslot
    {
        public String id;
        public int keySize;           // master key size in bytes
        public long priority = 1;     // 0 = ignore, 1 = normal, 2 = high
        public long areaOffset, areaSize;
        public String areaEncryption; // e.g. aes-xts-plain64
        public int areaKeySize;
        public Kdf kdf;
        public int afStripes;
        public String afHash;
    }

    public static final class Segment
    {
        public String id;
        public long offset;
        public long size;             // -1 = dynamic (to end of device)
        public long ivTweak;
        public String encryption;     // e.g. aes-xts-plain64
        public int sectorSize;
    }

    public static final class Digest
    {
        public String id;
        public List<String> keyslots, segments;
        public String hash;
        public long iterations;
        public byte[] salt, digest;
    }

    public long hdrSize, seqid, keyslotsSize;
    public String label, subsystem, uuid, checksumAlg;
    public boolean usedSecondary;     // primary was damaged; secondary used
    public boolean copiesOutOfSync;   // both valid but seqid differ (must be repaired before any write)
    public final List<Keyslot> keyslots = new ArrayList<>();
    public final List<Segment> segments = new ArrayList<>();
    public final List<Digest> digests = new ArrayList<>();
    public List<String> configFlags = Collections.emptyList();
    public final List<String> warnings = new ArrayList<>();

    // ---------------------------------------------------------------- reading

    public static boolean hasLuks2Magic(Source src) throws IOException
    {
        if (src.size() < BIN_SIZE)
            return false;
        byte[] b = new byte[8];
        src.readFully(0, b, 0, 8);
        return Arrays.equals(Arrays.copyOf(b, 6), MAGIC1) && b[6] == 0 && b[7] == 2;
    }

    public static Luks2Header read(Source src) throws IOException
    {
        long devSize = src.size();
        Raw primary = null, secondary = null;
        String primaryErr = null, secondaryErr = null;
        try { primary = Raw.load(src, 0, devSize, null); }
        catch (Luks2Exception e) { primaryErr = e.getMessage(); }

        // Secondary sits right after the primary area; if the primary is unreadable,
        // probe every legal header size like cryptsetup does.
        long[] probe = primary != null ? new long[]{primary.hdrSize} : HDR_SIZES;
        for (long off : probe)
        {
            try { secondary = Raw.load(src, off, devSize, primary); break; }
            catch (Luks2Exception e) { secondaryErr = e.getMessage(); }
        }
        if (primary == null && secondary == null)
            throw new Luks2Exception("no valid LUKS2 header (primary: " + primaryErr + "; secondary: " + secondaryErr + ")");

        Raw use;
        Luks2Header h;
        if (primary != null && secondary != null)
        {
            use = secondary.seqid > primary.seqid ? secondary : primary;
            h = parse(use, devSize);
            h.copiesOutOfSync = primary.seqid != secondary.seqid;
            if (h.copiesOutOfSync)
                h.warnings.add("primary/secondary header seqid differ (" + primary.seqid + " vs " + secondary.seqid + "); using newer");
        }
        else
        {
            use = primary != null ? primary : secondary;
            h = parse(use, devSize);
            h.copiesOutOfSync = true;
            h.warnings.add(primary == null ? "primary header damaged (" + primaryErr + "); using secondary"
                                           : "secondary header damaged (" + secondaryErr + ")");
        }
        h.usedSecondary = use == secondary;
        return h;
    }

    /** One binary header + JSON area, checksum verified. */
    private static final class Raw
    {
        long hdrSize, seqid, hdrOffset;
        String label, csumAlg, uuid, subsystem, json;

        static Raw load(Source src, long off, long devSize, Raw other) throws IOException
        {
            if (off + BIN_SIZE > devSize)
                throw new Luks2Exception("header beyond end of device");
            byte[] bin = new byte[BIN_SIZE];
            src.readFully(off, bin, 0, BIN_SIZE);
            ByteBuffer bb = ByteBuffer.wrap(bin); // big-endian
            byte[] magic = Arrays.copyOf(bin, 6);
            if (!Arrays.equals(magic, off == 0 ? MAGIC1 : MAGIC2))
                throw new Luks2Exception("bad magic at " + off);
            if (bb.getShort(6) != 2)
                throw new Luks2Exception("not LUKS version 2");
            Raw r = new Raw();
            r.hdrSize = bb.getLong(8);
            r.seqid = bb.getLong(16);
            r.hdrOffset = bb.getLong(256);
            if (Arrays.binarySearch(HDR_SIZES, r.hdrSize) < 0)
                throw new Luks2Exception("illegal hdr_size " + r.hdrSize);
            if (r.hdrOffset != off)
                throw new Luks2Exception("hdr_offset " + r.hdrOffset + " != actual " + off);
            if (off != 0 && off != r.hdrSize)
                throw new Luks2Exception("secondary header not at hdr_size");
            if (other != null && other.hdrSize != r.hdrSize)
                throw new Luks2Exception("hdr_size differs between copies");
            if (off + r.hdrSize > devSize)
                throw new Luks2Exception("header area beyond end of device");
            r.label = cstr(bin, 24, 48);
            r.csumAlg = cstr(bin, 72, 32);
            r.uuid = cstr(bin, 168, 40);
            r.subsystem = cstr(bin, 208, 48);

            byte[] area = new byte[(int) r.hdrSize];
            System.arraycopy(bin, 0, area, 0, BIN_SIZE);
            src.readFully(off + BIN_SIZE, area, BIN_SIZE, area.length - BIN_SIZE);
            byte[] stored = Arrays.copyOfRange(area, CSUM_OFF, CSUM_OFF + CSUM_LEN);
            Arrays.fill(area, CSUM_OFF, CSUM_OFF + CSUM_LEN, (byte) 0);
            MessageDigest md;
            try { md = MessageDigest.getInstance(javaHashName(r.csumAlg)); }
            catch (NoSuchAlgorithmException e) { throw new Luks2Exception("unsupported checksum " + r.csumAlg); }
            byte[] calc = Arrays.copyOf(md.digest(area), CSUM_LEN);
            if (!MessageDigest.isEqual(calc, stored))
                throw new Luks2Exception("checksum mismatch at " + off);

            int end = BIN_SIZE;
            while (end < area.length && area[end] != 0) end++;
            if (end == area.length)
                throw new Luks2Exception("JSON area not NUL-terminated");
            r.json = new String(area, BIN_SIZE, end - BIN_SIZE, StandardCharsets.UTF_8);
            return r;
        }
    }

    // ---------------------------------------------------------------- parsing

    private static Luks2Header parse(Raw r, long devSize) throws Luks2Exception
    {
        Luks2Header h = new Luks2Header();
        h.hdrSize = r.hdrSize;
        h.seqid = r.seqid;
        h.label = r.label;
        h.uuid = r.uuid;
        h.subsystem = r.subsystem;
        h.checksumAlg = r.csumAlg;

        Map<String, Object> root = obj(Json.parse(r.json), "root");
        Map<String, Object> config = obj(root.get("config"), "config");
        long jsonSize = u64(config.get("json_size"), "config.json_size");
        h.keyslotsSize = u64(config.get("keyslots_size"), "config.keyslots_size");
        if (jsonSize != r.hdrSize - BIN_SIZE)
            throw new Luks2Exception("config.json_size inconsistent with hdr_size");
        if (config.containsKey("flags"))
            h.configFlags = strList(config.get("flags"), "config.flags");
        if (config.containsKey("requirements"))
        {
            Map<String, Object> req = obj(config.get("requirements"), "config.requirements");
            if (req.containsKey("mandatory") && !list(req.get("mandatory"), "requirements.mandatory").isEmpty())
                throw new Luks2Exception("volume has mandatory requirements " + req.get("mandatory")
                        + " (e.g. re-encryption in progress); refusing to open");
        }

        long areaStart = 2 * r.hdrSize, areaEnd = areaStart + h.keyslotsSize;
        if (h.keyslotsSize < 0 || h.keyslotsSize % 4096 != 0)
            throw new Luks2Exception("bad keyslots_size");
        if (areaEnd > devSize)
            throw new Luks2Exception("keyslots area extends beyond end of device (truncated device?)");

        for (Map.Entry<String, Object> e : obj(root.get("keyslots"), "keyslots").entrySet())
        {
            Map<String, Object> ks = obj(e.getValue(), "keyslot " + e.getKey());
            String type = str(ks.get("type"), "keyslot.type");
            if ("reencrypt".equals(type))
                throw new Luks2Exception("re-encryption keyslot present: re-encryption in progress; refusing to open");
            if (!"luks2".equals(type))
            {
                h.warnings.add("ignoring keyslot " + e.getKey() + " of unknown type " + type);
                continue;
            }
            Keyslot k = new Keyslot();
            k.id = e.getKey();
            k.keySize = (int) num(ks.get("key_size"), "keyslot.key_size", 1, 512);
            if (ks.containsKey("priority"))
                k.priority = num(ks.get("priority"), "keyslot.priority", 0, 2);
            Map<String, Object> area = obj(ks.get("area"), "keyslot.area");
            if (!"raw".equals(str(area.get("type"), "area.type")))
                throw new Luks2Exception("unsupported keyslot area type " + area.get("type"));
            k.areaOffset = u64(area.get("offset"), "area.offset");
            k.areaSize = u64(area.get("size"), "area.size");
            k.areaEncryption = str(area.get("encryption"), "area.encryption");
            k.areaKeySize = (int) num(area.get("key_size"), "area.key_size", 1, 512);
            if (k.areaOffset < areaStart || k.areaOffset + k.areaSize > areaEnd || k.areaOffset % 512 != 0)
                throw new Luks2Exception("keyslot " + k.id + " area outside keyslots area");

            Map<String, Object> af = obj(ks.get("af"), "keyslot.af");
            if (!"luks1".equals(str(af.get("type"), "af.type")))
                throw new Luks2Exception("unsupported AF type " + af.get("type"));
            k.afStripes = (int) num(af.get("stripes"), "af.stripes", 1, 4000);
            k.afHash = str(af.get("hash"), "af.hash");
            if ((long) k.keySize * k.afStripes > k.areaSize)
                throw new Luks2Exception("keyslot " + k.id + " AF material larger than area");

            Map<String, Object> kd = obj(ks.get("kdf"), "keyslot.kdf");
            Kdf kdf = new Kdf();
            kdf.type = str(kd.get("type"), "kdf.type");
            kdf.salt = b64(kd.get("salt"), "kdf.salt");
            switch (kdf.type)
            {
                case "pbkdf2":
                    kdf.hash = str(kd.get("hash"), "kdf.hash");
                    kdf.iterations = num(kd.get("iterations"), "kdf.iterations", 1, Integer.MAX_VALUE);
                    break;
                case "argon2i":
                case "argon2id":
                    kdf.time = num(kd.get("time"), "kdf.time", 1, 1L << 32);
                    kdf.memoryKiB = num(kd.get("memory"), "kdf.memory", 8, 4L * 1024 * 1024);
                    kdf.cpus = num(kd.get("cpus"), "kdf.cpus", 1, 1L << 24);
                    break;
                default:
                    throw new Luks2Exception("unsupported KDF " + kdf.type);
            }
            k.kdf = kdf;
            h.keyslots.add(k);
        }
        // Keyslot areas must not overlap each other.
        List<Keyslot> sorted = new ArrayList<>(h.keyslots);
        sorted.sort((a, b) -> Long.compare(a.areaOffset, b.areaOffset));
        for (int i = 1; i < sorted.size(); i++)
            if (sorted.get(i - 1).areaOffset + sorted.get(i - 1).areaSize > sorted.get(i).areaOffset)
                throw new Luks2Exception("overlapping keyslot areas");

        Map<String, Object> segs = obj(root.get("segments"), "segments");
        if (segs.size() != 1)
            throw new Luks2Exception(segs.size() + " segments (re-encryption in progress or unsupported layout); refusing to open");
        for (Map.Entry<String, Object> e : segs.entrySet())
        {
            Map<String, Object> sg = obj(e.getValue(), "segment " + e.getKey());
            if (!"crypt".equals(str(sg.get("type"), "segment.type")))
                throw new Luks2Exception("unsupported segment type " + sg.get("type"));
            if (sg.containsKey("flags") && !list(sg.get("flags"), "segment.flags").isEmpty())
                throw new Luks2Exception("segment flags " + sg.get("flags") + " (re-encryption in progress?); refusing to open");
            if (sg.containsKey("integrity"))
                throw new Luks2Exception("dm-integrity (authenticated encryption) segments are not supported");
            Segment s = new Segment();
            s.id = e.getKey();
            s.offset = u64(sg.get("offset"), "segment.offset");
            Object size = sg.get("size");
            s.size = "dynamic".equals(size) ? -1 : u64(size, "segment.size");
            s.ivTweak = u64(sg.get("iv_tweak"), "segment.iv_tweak");
            s.encryption = str(sg.get("encryption"), "segment.encryption");
            s.sectorSize = (int) num(sg.get("sector_size"), "segment.sector_size", 512, 4096);
            if (Integer.bitCount(s.sectorSize) != 1)
                throw new Luks2Exception("bad sector_size");
            if (s.offset < areaEnd || s.offset % s.sectorSize != 0)
                throw new Luks2Exception("segment overlaps header/keyslots or is misaligned");
            if (s.offset > devSize || (s.size >= 0 && (s.size % s.sectorSize != 0 || s.offset + s.size > devSize)))
                throw new Luks2Exception("segment extends beyond end of device");
            h.segments.add(s);
        }

        for (Map.Entry<String, Object> e : obj(root.get("digests"), "digests").entrySet())
        {
            Map<String, Object> dg = obj(e.getValue(), "digest " + e.getKey());
            if (!"pbkdf2".equals(str(dg.get("type"), "digest.type")))
                throw new Luks2Exception("unsupported digest type " + dg.get("type"));
            Digest d = new Digest();
            d.id = e.getKey();
            d.keyslots = strList(dg.get("keyslots"), "digest.keyslots");
            d.segments = strList(dg.get("segments"), "digest.segments");
            d.hash = str(dg.get("hash"), "digest.hash");
            d.iterations = num(dg.get("iterations"), "digest.iterations", 1, Integer.MAX_VALUE);
            d.salt = b64(dg.get("salt"), "digest.salt");
            d.digest = b64(dg.get("digest"), "digest.digest");
            h.digests.add(d);
        }
        if (h.digests.isEmpty())
            throw new Luks2Exception("no digests");
        return h;
    }

    // ---------------------------------------------------------------- helpers

    public static String javaHashName(String luksName) throws Luks2Exception
    {
        switch (luksName.toLowerCase())
        {
            case "sha1": return "SHA-1";
            case "sha256": return "SHA-256";
            case "sha512": return "SHA-512";
            case "sha384": return "SHA-384";
            default: throw new Luks2Exception("unsupported hash " + luksName);
        }
    }

    private static String cstr(byte[] b, int off, int max)
    {
        int n = 0;
        while (n < max && b[off + n] != 0) n++;
        return new String(b, off, n, StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o, String what) throws Luks2Exception
    {
        if (!(o instanceof Map)) throw new Luks2Exception(what + ": expected object");
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object o, String what) throws Luks2Exception
    {
        if (!(o instanceof List)) throw new Luks2Exception(what + ": expected array");
        return (List<Object>) o;
    }

    private static List<String> strList(Object o, String what) throws Luks2Exception
    {
        List<String> r = new ArrayList<>();
        for (Object x : list(o, what)) r.add(str(x, what));
        return r;
    }

    private static String str(Object o, String what) throws Luks2Exception
    {
        if (!(o instanceof String)) throw new Luks2Exception(what + ": expected string");
        return (String) o;
    }

    /** LUKS2 stores 64-bit values as decimal strings. */
    private static long u64(Object o, String what) throws Luks2Exception
    {
        String s = str(o, what);
        if (s.isEmpty() || s.length() > 19 || !s.chars().allMatch(Character::isDigit))
            throw new Luks2Exception(what + ": bad u64 \"" + s + "\"");
        return Long.parseLong(s);
    }

    private static long num(Object o, String what, long min, long max) throws Luks2Exception
    {
        if (!(o instanceof Long)) throw new Luks2Exception(what + ": expected number");
        long v = (Long) o;
        if (v < min || v > max) throw new Luks2Exception(what + ": out of range (" + v + ")");
        return v;
    }

    private static byte[] b64(Object o, String what) throws Luks2Exception
    {
        try { return java.util.Base64.getDecoder().decode(str(o, what)); }
        catch (IllegalArgumentException e) { throw new Luks2Exception(what + ": bad base64"); }
    }
}
