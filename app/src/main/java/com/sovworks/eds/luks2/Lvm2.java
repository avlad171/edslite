package com.sovworks.eds.luks2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Read-only LVM2 support for a single physical volume (the common
 * "LUKS -> LVM -> ext4" Linux install layout). Pure Java, no Android deps.
 *
 * Verifies the label CRC, the metadata-area header CRC and the metadata text
 * CRC. Only linear logical volumes ("striped" with stripe_count 1, whose
 * extents all live on this PV) are exposed; everything else (thin, raid,
 * cache, snapshot, multi-PV) is listed as unsupported.
 */
public final class Lvm2
{
    public static final class LogicalVolume implements Luks2Header.Source
    {
        public final String name;
        public final long size;
        final long[][] segs; // {lvStart, length, pvOffset} in bytes
        final Luks2Header.Source pv;

        LogicalVolume(String name, long size, long[][] segs, Luks2Header.Source pv)
        {
            this.name = name;
            this.size = size;
            this.segs = segs;
            this.pv = pv;
        }

        @Override public long size() { return size; }

        public int segsCount() { return segs.length; }

        @Override
        public void readFully(long off, byte[] buf, int bufOff, int len) throws IOException
        {
            if (off < 0 || len < 0 || off + len > size)
                throw new IOException("read outside logical volume " + name);
            while (len > 0)
            {
                long[] s = find(off);
                int n = (int) Math.min(len, s[0] + s[1] - off);
                pv.readFully(s[2] + (off - s[0]), buf, bufOff, n);
                off += n; bufOff += n; len -= n;
            }
        }

        private long[] find(long off) throws IOException
        {
            for (long[] s : segs)
                if (off >= s[0] && off < s[0] + s[1])
                    return s;
            throw new IOException("unmapped LV offset " + off);
        }
    }

    public String vgName;
    public long seqno;
    public final Map<String, LogicalVolume> volumes = new LinkedHashMap<>();
    public final Map<String, String> unsupported = new LinkedHashMap<>(); // name -> reason

    private static final int SECTOR = 512;
    private static final String MDA_MAGIC = " LVM2 x[5A%r0N*>";
    private static final int INITIAL_CRC = 0xf597a6cf;

    public static boolean hasLabel(Luks2Header.Source pv) throws IOException
    {
        return findLabel(pv) >= 0;
    }

    private static long findLabel(Luks2Header.Source pv) throws IOException
    {
        byte[] s = new byte[SECTOR];
        for (int i = 0; i < 4; i++)
        {
            if ((i + 1) * SECTOR > pv.size()) break;
            pv.readFully((long) i * SECTOR, s, 0, SECTOR);
            if (new String(s, 0, 8, StandardCharsets.US_ASCII).equals("LABELONE"))
                return (long) i * SECTOR;
        }
        return -1;
    }

    public static Lvm2 read(Luks2Header.Source pv) throws IOException
    {
        long lo = findLabel(pv);
        if (lo < 0)
            throw new Luks2Exception("LVM: no label");
        byte[] lb = new byte[SECTOR];
        pv.readFully(lo, lb, 0, SECTOR);
        ByteBuffer l = ByteBuffer.wrap(lb).order(ByteOrder.LITTLE_ENDIAN);
        if (l.getLong(8) != lo / SECTOR)
            throw new Luks2Exception("LVM: label sector mismatch");
        if (l.getInt(16) != crc(INITIAL_CRC, lb, 20, SECTOR - 20))
            throw new Luks2Exception("LVM: label checksum mismatch");
        if (!new String(lb, 24, 8, StandardCharsets.US_ASCII).equals("LVM2 001"))
            throw new Luks2Exception("LVM: unsupported label type");
        int pvh = l.getInt(20);
        if (pvh < 32 || pvh > SECTOR - 48)
            throw new Luks2Exception("LVM: bad pv_header offset");
        String pvUuid = new String(lb, pvh, 32, StandardCharsets.US_ASCII);

        // data areas list, then metadata areas list, each zero-terminated
        int o = pvh + 40;
        List<long[]> mdas = new ArrayList<>();
        for (int list = 0; list < 2; list++)
            while (true)
            {
                if (o + 16 > SECTOR) throw new Luks2Exception("LVM: unterminated area list");
                long off = l.getLong(o), size = l.getLong(o + 8);
                o += 16;
                if (off == 0 && size == 0) break;
                if (list == 1) mdas.add(new long[]{off, size});
            }
        if (mdas.isEmpty())
            throw new Luks2Exception("LVM: PV has no metadata area");

        String text = null;
        Luks2Exception last = null;
        for (long[] m : mdas)
            try { text = readMetadata(pv, m[0], m[1]); break; }
            catch (Luks2Exception e) { last = e; }
        if (text == null)
            throw last;

        Lvm2 r = new Lvm2();
        r.parse(text, pvUuid, pv);
        return r;
    }

    private static String readMetadata(Luks2Header.Source pv, long mdaOff, long mdaSize) throws IOException
    {
        if (mdaOff < 0 || mdaSize < 2 * SECTOR || mdaOff + mdaSize > pv.size())
            throw new Luks2Exception("LVM: metadata area out of bounds");
        byte[] hb = new byte[SECTOR];
        pv.readFully(mdaOff, hb, 0, SECTOR);
        ByteBuffer h = ByteBuffer.wrap(hb).order(ByteOrder.LITTLE_ENDIAN);
        if (h.getInt(0) != crc(INITIAL_CRC, hb, 4, SECTOR - 4))
            throw new Luks2Exception("LVM: metadata header checksum mismatch");
        if (!new String(hb, 4, 16, StandardCharsets.US_ASCII).equals(MDA_MAGIC) || h.getInt(20) != 1)
            throw new Luks2Exception("LVM: bad metadata header");
        if (h.getLong(24) != mdaOff || h.getLong(32) != mdaSize)
            throw new Luks2Exception("LVM: metadata header start/size mismatch");
        long tOff = h.getLong(40), tSize = h.getLong(48);
        int tCrc = h.getInt(56);
        if (tSize <= 0 || tSize > 16 << 20 || tOff < SECTOR || tOff >= mdaSize)
            throw new Luks2Exception("LVM: bad metadata location");
        byte[] t = new byte[(int) tSize];
        long first = Math.min(tSize, mdaSize - tOff);
        pv.readFully(mdaOff + tOff, t, 0, (int) first);
        if (first < tSize) // circular buffer wraps to just after the header
            pv.readFully(mdaOff + SECTOR, t, (int) first, (int) (tSize - first));
        if (crc(INITIAL_CRC, t, 0, t.length) != tCrc)
            throw new Luks2Exception("LVM: metadata text checksum mismatch");
        int end = 0;
        while (end < t.length && t[end] != 0) end++;
        return new String(t, 0, end, StandardCharsets.UTF_8);
    }

    /** LVM's calc_crc: reflected CRC-32 (0xEDB88320), custom seed, no final xor. */
    static int crc(int crc, byte[] b, int off, int len)
    {
        for (int i = off; i < off + len; i++)
        {
            crc ^= b[i] & 0xff;
            for (int k = 0; k < 8; k++)
                crc = (crc >>> 1) ^ (0xEDB88320 & -(crc & 1));
        }
        return crc;
    }

    // ------------------------------------------------------------ metadata

    @SuppressWarnings("unchecked")
    private void parse(String text, String pvUuid, Luks2Header.Source pv) throws IOException
    {
        Map<String, Object> root = new ConfigParser(text).parse();
        Map<String, Object> vg = null;
        for (Map.Entry<String, Object> e : root.entrySet())
            if (e.getValue() instanceof Map)
            {
                if (vg != null) throw new Luks2Exception("LVM: more than one VG in metadata");
                vgName = e.getKey();
                vg = (Map<String, Object>) e.getValue();
            }
        if (vg == null) throw new Luks2Exception("LVM: no VG in metadata");
        seqno = num(vg, "seqno");
        long extent = num(vg, "extent_size") * SECTOR;
        if (extent <= 0) throw new Luks2Exception("LVM: bad extent_size");

        String pvName = null;
        long peStart = 0, peCount = 0;
        for (Map.Entry<String, Object> e : sect(vg, "physical_volumes").entrySet())
        {
            Map<String, Object> p = (Map<String, Object>) e.getValue();
            if (str(p, "id").replace("-", "").equals(pvUuid))
            {
                pvName = e.getKey();
                peStart = num(p, "pe_start") * SECTOR;
                peCount = num(p, "pe_count");
            }
        }
        if (pvName == null) throw new Luks2Exception("LVM: this PV is not in the VG metadata");
        if (peStart + peCount * extent > pv.size())
            throw new Luks2Exception("LVM: PV extents beyond end of device");

        Object lvsObj = vg.get("logical_volumes");
        if (!(lvsObj instanceof Map)) return;
        for (Map.Entry<String, Object> e : ((Map<String, Object>) lvsObj).entrySet())
        {
            String name = e.getKey();
            Map<String, Object> lv = (Map<String, Object>) e.getValue();
            List<Object> status = lv.get("status") instanceof List ? (List<Object>) lv.get("status") : java.util.Collections.emptyList();
            if (!status.contains("VISIBLE")) continue; // internal LVs
            long count = num(lv, "segment_count");
            List<long[]> segs = new ArrayList<>();
            String why = null;
            long expect = 0;
            for (int i = 1; i <= count && why == null; i++)
            {
                Map<String, Object> s = sect(lv, "segment" + i);
                String type = str(s, "type");
                if (!"striped".equals(type)) { why = "segment type " + type; break; }
                if (num(s, "stripe_count") != 1) { why = "striped across PVs"; break; }
                List<Object> stripes = (List<Object>) s.get("stripes");
                if (stripes == null || stripes.size() != 2 || !pvName.equals(stripes.get(0))) { why = "extents on another PV"; break; }
                long start = num(s, "start_extent"), n = num(s, "extent_count"), pe = (Long) stripes.get(1);
                if (start != expect) { why = "non-contiguous segments"; break; }
                if (pe < 0 || n <= 0 || pe + n > peCount) { why = "extents out of PV range"; break; }
                segs.add(new long[]{start * extent, n * extent, peStart + pe * extent});
                expect = start + n;
            }
            if (why != null)
                unsupported.put(name, why);
            else
                volumes.put(name, new LogicalVolume(name, expect * extent, segs.toArray(new long[0][]), pv));
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> sect(Map<String, Object> m, String k) throws Luks2Exception
    {
        Object o = m.get(k);
        if (!(o instanceof Map)) throw new Luks2Exception("LVM: missing section " + k);
        return (Map<String, Object>) o;
    }

    private static long num(Map<String, Object> m, String k) throws Luks2Exception
    {
        Object o = m.get(k);
        if (!(o instanceof Long)) throw new Luks2Exception("LVM: missing number " + k);
        return (Long) o;
    }

    private static String str(Map<String, Object> m, String k) throws Luks2Exception
    {
        Object o = m.get(k);
        if (!(o instanceof String)) throw new Luks2Exception("LVM: missing string " + k);
        return (String) o;
    }

    /** LVM text config: key = value | key { ... }, values: int, "string", [list], # comments. */
    private static final class ConfigParser
    {
        private final String s;
        private int i, depth;

        ConfigParser(String s) { this.s = s; }

        Map<String, Object> parse() throws Luks2Exception
        {
            Map<String, Object> m = section(true);
            ws();
            if (i != s.length()) throw err("trailing data");
            return m;
        }

        private Map<String, Object> section(boolean top) throws Luks2Exception
        {
            if (++depth > 16) throw err("nesting too deep");
            Map<String, Object> m = new LinkedHashMap<>();
            while (true)
            {
                ws();
                if (i >= s.length()) { if (top) break; throw err("unexpected end"); }
                if (s.charAt(i) == '}') { if (top) throw err("unbalanced }"); i++; break; }
                String key = ident();
                ws();
                if (i >= s.length()) throw err("unexpected end");
                char c = s.charAt(i++);
                Object v;
                if (c == '{') v = section(false);
                else if (c == '=') { ws(); v = value(); }
                else throw err("expected = or {");
                if (m.put(key, v) != null) throw err("duplicate key " + key);
            }
            depth--;
            return m;
        }

        private Object value() throws Luks2Exception
        {
            if (i >= s.length()) throw err("unexpected end");
            char c = s.charAt(i);
            if (c == '"') return string();
            if (c == '[')
            {
                i++;
                List<Object> l = new ArrayList<>();
                while (true)
                {
                    ws();
                    if (i < s.length() && s.charAt(i) == ']') { i++; return l; }
                    l.add(value());
                    ws();
                    if (i < s.length() && s.charAt(i) == ',') i++;
                }
            }
            int st = i;
            if (c == '-') i++;
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            if (i < s.length() && s.charAt(i) == '.') // floats appear only in a few optional fields
            {
                i++;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
                return s.substring(st, i);
            }
            if (st == i || (c == '-' && i == st + 1)) throw err("bad value");
            try { return Long.parseLong(s.substring(st, i)); }
            catch (NumberFormatException e) { throw err("bad number"); }
        }

        private String string() throws Luks2Exception
        {
            StringBuilder b = new StringBuilder();
            i++;
            while (true)
            {
                if (i >= s.length()) throw err("unterminated string");
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c == '\\') { if (i >= s.length()) throw err("bad escape"); c = s.charAt(i++); }
                b.append(c);
            }
        }

        private String ident() throws Luks2Exception
        {
            int st = i;
            while (i < s.length() && (Character.isLetterOrDigit(s.charAt(i)) || "_.+-".indexOf(s.charAt(i)) >= 0)) i++;
            if (st == i) throw err("expected identifier");
            return s.substring(st, i);
        }

        private void ws()
        {
            while (i < s.length())
            {
                char c = s.charAt(i);
                if (c == '#') { while (i < s.length() && s.charAt(i) != '\n') i++; }
                else if (Character.isWhitespace(c)) i++;
                else break;
            }
        }

        private Luks2Exception err(String m) { return new Luks2Exception("LVM metadata: " + m + " at " + i); }
    }
}
