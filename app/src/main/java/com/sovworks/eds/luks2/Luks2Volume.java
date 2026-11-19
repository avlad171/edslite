package com.sovworks.eds.luks2;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * An unlocked LUKS2 volume: read-only access to the decrypted data segment.
 *
 * One-time work (KDF dispatch, AF merge, digest check) is Java; Argon2 and
 * the per-sector AES-XTS decryption are native (libedsluks).
 *
 * Reads are bounds-checked against the segment; there is no write path.
 */
public final class Luks2Volume implements Closeable, Luks2Header.Source
{
    public interface ProgressListener
    {
        void onKeyslot(String keyslotId, String kdfType);
    }

    public static Luks2Volume unlock(Luks2Header.Source src, Luks2Header hdr, byte[] passphrase,
                                     ProgressListener progress) throws IOException
    {
        Luks2Native.ensureLoaded();
        Luks2Header.Segment seg = hdr.segments.get(0);
        if (!isSupportedCipher(seg.encryption))
            throw new Luks2Exception("unsupported data cipher " + seg.encryption);

        // Try keyslots by priority (2 first, then 1; 0 = "ignore unless explicitly asked").
        for (int prio = 2; prio >= 1; prio--)
            for (Luks2Header.Keyslot ks : hdr.keyslots)
            {
                if (ks.priority != prio)
                    continue;
                Luks2Header.Digest dg = digestFor(hdr, ks.id, seg.id);
                if (dg == null)
                    continue;
                if (progress != null)
                    progress.onKeyslot(ks.id, ks.kdf.type);
                byte[] mk = openKeyslot(src, ks, passphrase);
                try
                {
                    if (verify(dg, mk))
                    {
                        long size = seg.size >= 0 ? seg.size : (src.size() - seg.offset) / seg.sectorSize * seg.sectorSize;
                        long h = Luks2Native.xtsNew(mk);
                        if (h == 0)
                            throw new Luks2Exception("bad master key size " + mk.length);
                        return new Luks2Volume(src, seg, size, h);
                    }
                }
                finally
                {
                    Arrays.fill(mk, (byte) 0);
                }
            }
        throw new Luks2WrongPassphraseException();
    }

    static boolean isSupportedCipher(String spec)
    {
        return "aes-xts-plain64".equals(spec);
    }

    private static Luks2Header.Digest digestFor(Luks2Header hdr, String keyslot, String segment)
    {
        for (Luks2Header.Digest d : hdr.digests)
            if (d.keyslots.contains(keyslot) && d.segments.contains(segment))
                return d;
        return null;
    }

    private static byte[] openKeyslot(Luks2Header.Source src, Luks2Header.Keyslot ks, byte[] pw) throws IOException
    {
        if (!isSupportedCipher(ks.areaEncryption))
            throw new Luks2Exception("unsupported keyslot cipher " + ks.areaEncryption);
        byte[] areaKey = new byte[ks.areaKeySize];
        byte[] material = null;
        long h = 0;
        try
        {
            Luks2Header.Kdf k = ks.kdf;
            if ("pbkdf2".equals(k.type))
                pbkdf2(k.hash, pw, k.salt, (int) k.iterations, areaKey);
            else
            {
                int r = Luks2Native.argon2("argon2i".equals(k.type) ? Luks2Native.ARGON2I : Luks2Native.ARGON2ID,
                        pw, k.salt, (int) k.time, (int) k.memoryKiB, (int) k.cpus, areaKey);
                if (r != 0)
                    throw new Luks2Exception("Argon2 failed: " + Luks2Native.argon2Error(r)
                            + (r == -22 ? " (needs " + k.memoryKiB / 1024 + " MiB of RAM)" : ""));
            }
            int n = ks.keySize * ks.afStripes;
            int nAligned = (n + 511) / 512 * 512;
            if (nAligned > ks.areaSize)
                throw new Luks2Exception("keyslot area too small");
            material = new byte[nAligned];
            src.readFully(ks.areaOffset, material, 0, nAligned);
            h = Luks2Native.xtsNew(areaKey);
            if (h == 0)
                throw new Luks2Exception("bad keyslot key size");
            int r = Luks2Native.xtsDecrypt(h, material, 0, nAligned, 512, 0);
            if (r != 0)
                throw new Luks2Exception("keyslot decrypt failed (" + r + ")");
            return afMerge(material, ks.keySize, ks.afStripes, ks.afHash);
        }
        finally
        {
            if (h != 0) Luks2Native.xtsFree(h);
            Arrays.fill(areaKey, (byte) 0);
            if (material != null) Arrays.fill(material, (byte) 0);
        }
    }

    /** LUKS anti-forensic merge (same as LUKS1). */
    static byte[] afMerge(byte[] src, int keySize, int stripes, String hash) throws Luks2Exception
    {
        MessageDigest md;
        try { md = MessageDigest.getInstance(Luks2Header.javaHashName(hash)); }
        catch (GeneralSecurityException e) { throw new Luks2Exception("unsupported AF hash " + hash); }
        byte[] d = new byte[keySize];
        for (int i = 0; i < stripes - 1; i++)
        {
            for (int j = 0; j < keySize; j++)
                d[j] ^= src[i * keySize + j];
            diffuse(md, d);
        }
        byte[] key = new byte[keySize];
        for (int j = 0; j < keySize; j++)
            key[j] = (byte) (d[j] ^ src[(stripes - 1) * keySize + j]);
        Arrays.fill(d, (byte) 0);
        return key;
    }

    private static void diffuse(MessageDigest md, byte[] buf)
    {
        int ds = md.getDigestLength();
        byte[] out = new byte[buf.length];
        for (int i = 0, off = 0; off < buf.length; i++, off += ds)
        {
            int len = Math.min(ds, buf.length - off);
            md.reset();
            md.update(ByteBuffer.allocate(4).putInt(i).array());
            md.update(buf, off, len);
            System.arraycopy(md.digest(), 0, out, off, len);
        }
        System.arraycopy(out, 0, buf, 0, buf.length);
        Arrays.fill(out, (byte) 0);
    }

    private static boolean verify(Luks2Header.Digest d, byte[] mk) throws Luks2Exception
    {
        byte[] calc = new byte[d.digest.length];
        pbkdf2(d.hash, mk, d.salt, (int) d.iterations, calc);
        return MessageDigest.isEqual(calc, d.digest);
    }

    /**
     * PBKDF2 over raw bytes. (PBEKeySpec takes char[] and would mangle binary
     * keys, so this is a straightforward HMAC implementation.)
     */
    static void pbkdf2(String hash, byte[] password, byte[] salt, int iterations, byte[] out) throws Luks2Exception
    {
        try
        {
            if (password.length == 0)
                throw new Luks2Exception("empty password"); // SecretKeySpec forbids empty keys
            String alg = "Hmac" + Luks2Header.javaHashName(hash).replace("-", "");
            Mac mac = Mac.getInstance(alg);
            mac.init(new SecretKeySpec(password, alg));
            int hl = mac.getMacLength();
            byte[] u = new byte[hl], t = new byte[hl];
            for (int block = 1, off = 0; off < out.length; block++, off += hl)
            {
                mac.update(salt);
                mac.update(ByteBuffer.allocate(4).putInt(block).array());
                mac.doFinal(u, 0);
                System.arraycopy(u, 0, t, 0, hl);
                for (int i = 1; i < iterations; i++)
                {
                    mac.update(u);
                    mac.doFinal(u, 0);
                    for (int j = 0; j < hl; j++) t[j] ^= u[j];
                }
                System.arraycopy(t, 0, out, off, Math.min(hl, out.length - off));
            }
            Arrays.fill(u, (byte) 0);
            Arrays.fill(t, (byte) 0);
        }
        catch (GeneralSecurityException e)
        {
            throw new Luks2Exception("PBKDF2-" + hash + ": " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ data

    private final Luks2Header.Source _src;
    private final Luks2Header.Segment _seg;
    private final long _size;
    private long _xts;

    private Luks2Volume(Luks2Header.Source src, Luks2Header.Segment seg, long size, long xts)
    {
        _src = src;
        _seg = seg;
        _size = size;
        _xts = xts;
    }

    /** Size of the decrypted payload in bytes. */
    @Override
    public long size() { return _size; }

    @Override
    public void readFully(long off, byte[] buf, int bufOff, int len) throws IOException
    {
        read(off, buf, bufOff, len);
    }

    public int sectorSize() { return _seg.sectorSize; }

    /** Reads decrypted bytes [off, off+len) of the payload. */
    public synchronized void read(long off, byte[] buf, int bufOff, int len) throws IOException
    {
        if (_xts == 0)
            throw new IOException("volume closed");
        if (off < 0 || len < 0 || off + len > _size)
            throw new IOException("read outside LUKS segment");
        final int S = _seg.sectorSize;
        long first = off / S, last = (off + len + S - 1) / S;
        // Bounded chunks so huge reads don't allocate huge buffers.
        final int maxSectors = Math.max(1, (1 << 20) / S);
        long sec = first;
        int done = 0;
        byte[] tmp = new byte[(int) Math.min(last - first, maxSectors) * S];
        try
        {
            while (sec < last)
            {
                int n = (int) Math.min(last - sec, maxSectors);
                int bytes = n * S;
                _src.readFully(_seg.offset + sec * S, tmp, 0, bytes);
                // LUKS2 uses iv_large_sectors: IV counts in units of sector_size.
                int r = Luks2Native.xtsDecrypt(_xts, tmp, 0, bytes, S, sec + _seg.ivTweak);
                if (r != 0)
                    throw new IOException("decrypt failed (" + r + ")");
                int skip = sec == first ? (int) (off - first * S) : 0;
                int take = Math.min(bytes - skip, len - done);
                System.arraycopy(tmp, skip, buf, bufOff + done, take);
                done += take;
                sec += n;
            }
        }
        finally
        {
            Arrays.fill(tmp, (byte) 0);
        }
    }

    @Override
    public synchronized void close()
    {
        if (_xts != 0)
        {
            Luks2Native.xtsFree(_xts);
            _xts = 0;
        }
    }
}
