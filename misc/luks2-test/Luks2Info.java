import com.sovworks.eds.luks2.Luks2Header;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Read-only LUKS2 inspector for desktop testing. Opens the device with mode "r" only.
 * Usage: java Luks2Info /dev/rdisk2   (whole disk: scans GPT)   or   <image file>
 * Prints structure only; never prints salts, digests or key material.
 */
public class Luks2Info
{
    static class Part implements Luks2Header.Source
    {
        final RandomAccessFile f; final long base, len;
        Part(RandomAccessFile f, long base, long len) { this.f = f; this.base = base; this.len = len; }
        public long size() { return len; }
        public void readFully(long off, byte[] b, int o, int l) throws IOException
        {
            if (off < 0 || off + l > len) throw new IOException("read outside partition");
            // raw macOS devices need sector-aligned I/O
            long a = (base + off) & ~4095L, e = (base + off + l + 4095) & ~4095L;
            byte[] t = new byte[(int) (e - a)];
            synchronized (f) { f.seek(a); f.readFully(t); }
            System.arraycopy(t, (int) (base + off - a), b, o, l);
        }
    }

    public static void main(String[] a) throws Exception
    {
        try (RandomAccessFile f = new RandomAccessFile(a[0], "r"))
        {
            long devLen = a.length > 1 ? Long.parseLong(a[1]) : f.length();
            Part whole = new Part(f, 0, devLen);
            byte[] s = new byte[512];
            whole.readFully(512, s, 0, 512);
            if (new String(s, 0, 8, "ASCII").equals("EFI PART"))
            {
                ByteBuffer h = ByteBuffer.wrap(s).order(ByteOrder.LITTLE_ENDIAN);
                long elba = h.getLong(72); int n = h.getInt(80), esz = h.getInt(84);
                byte[] ents = new byte[n * esz];
                whole.readFully(elba * 512, ents, 0, ents.length);
                ByteBuffer e = ByteBuffer.wrap(ents).order(ByteOrder.LITTLE_ENDIAN);
                for (int i = 0; i < n; i++)
                {
                    long first = e.getLong(i * esz + 32), last = e.getLong(i * esz + 40);
                    if (first == 0) continue;
                    Part p = new Part(f, first * 512, (last - first + 1) * 512);
                    System.out.printf("partition %d: offset %d, %.1f GB%n", i + 1, p.base, p.len / 1e9);
                    inspect(p);
                }
            }
            else
                inspect(whole);
        }
    }

    static void inspect(Part p)
    {
        try
        {
            if (!Luks2Header.hasLuks2Magic(p)) { System.out.println("  not LUKS2"); return; }
            Luks2Header h = Luks2Header.read(p);
            System.out.printf("  LUKS2 uuid=%s label='%s' hdr_size=%d seqid=%d csum=%s keyslots_size=%d%n",
                    h.uuid, h.label, h.hdrSize, h.seqid, h.checksumAlg, h.keyslotsSize);
            System.out.println("  copies in sync: " + !h.copiesOutOfSync + (h.usedSecondary ? " (using secondary)" : ""));
            for (Luks2Header.Keyslot k : h.keyslots)
                System.out.printf("  keyslot %s: key %d B, %s area %s/%d B, kdf %s%s, af stripes %d %s, prio %d%n",
                        k.id, k.keySize, "raw", k.areaEncryption, k.areaKeySize, k.kdf.type,
                        k.kdf.type.equals("pbkdf2") ? " " + k.kdf.hash + " it=" + k.kdf.iterations
                                : " t=" + k.kdf.time + " m=" + k.kdf.memoryKiB + "KiB p=" + k.kdf.cpus,
                        k.afStripes, k.afHash, k.priority);
            for (Luks2Header.Segment g : h.segments)
                System.out.printf("  segment %s: %s, offset %d, size %s, sector %d, iv_tweak %d%n",
                        g.id, g.encryption, g.offset, g.size < 0 ? "dynamic" : String.valueOf(g.size), g.sectorSize, g.ivTweak);
            for (Luks2Header.Digest d : h.digests)
                System.out.printf("  digest %s: pbkdf2 %s it=%d keyslots=%s%n", d.id, d.hash, d.iterations, d.keyslots);
            if (!h.configFlags.isEmpty()) System.out.println("  config flags: " + h.configFlags);
            for (String w : h.warnings) System.out.println("  WARNING: " + w);
        }
        catch (IOException e)
        {
            System.out.println("  REFUSED: " + e.getMessage());
        }
    }
}
