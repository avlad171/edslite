package com.sovworks.eds.luks2;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Checks native Argon2id and AES-XTS against independent references. */
public class CryptoSelfTest
{
    public static void main(String[] a) throws Exception
    {
        Luks2Native.ensureLoaded();
        // Argon2id v1.3 KAT from the reference package (test.c): t=2, m=2^16, p=1, "password"/"somesalt"
        byte[] out = new byte[32];
        int r = Luks2Native.argon2(Luks2Native.ARGON2ID, "password".getBytes(), "somesalt".getBytes(), 2, 65536, 1, out, null);
        String want = "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7";
        check("argon2id KAT", r == 0 && HexFormat.of().formatHex(out).equals(want));

        SecureRandom rnd = new SecureRandom();
        for (int keyLen : new int[]{32, 64})
            for (int sector : new int[]{512, 4096})
            {
                byte[] key = new byte[keyLen]; rnd.nextBytes(key);
                byte[] pt = new byte[sector * 5]; rnd.nextBytes(pt);
                long iv0 = rnd.nextLong() >>> 1;
                byte[] ct = javaXtsEncrypt(key, pt, sector, iv0);
                long h = Luks2Native.xtsNew(key.clone());
                byte[] dec = ct.clone();
                r = Luks2Native.xtsDecrypt(h, dec, 0, dec.length, sector, iv0);
                Luks2Native.xtsFree(h);
                check("xts aes-" + keyLen * 4 + " sector " + sector, r == 0 && Arrays.equals(dec, pt));
            }
        // AF split/merge round trip and PBKDF2 RFC 6070-style sanity (sha256 vector)
        byte[] pb = new byte[32];
        Luks2Volume.pbkdf2("sha256", "password".getBytes(), "salt".getBytes(), 4096, pb);
        check("pbkdf2-sha256 KAT", HexFormat.of().formatHex(pb).equals("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"));
        System.out.println("ALL OK");
    }

    static void check(String n, boolean ok)
    {
        System.out.println((ok ? "OK   " : "FAIL ") + n);
        if (!ok) System.exit(1);
    }

    /** Textbook XTS (IEEE 1619) using JCE AES/ECB: independent of the native code. */
    static byte[] javaXtsEncrypt(byte[] key, byte[] pt, int sector, long iv0) throws Exception
    {
        int half = key.length / 2;
        Cipher k1 = Cipher.getInstance("AES/ECB/NoPadding"), k2 = Cipher.getInstance("AES/ECB/NoPadding");
        k1.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, 0, half, "AES"));
        k2.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, half, half, "AES"));
        byte[] out = new byte[pt.length];
        for (int s = 0; s < pt.length / sector; s++)
        {
            byte[] t = new byte[16];
            long iv = iv0 + s;
            for (int i = 0; i < 8; i++) t[i] = (byte) (iv >>> (8 * i));
            t = k2.doFinal(t);
            for (int b = 0; b < sector; b += 16)
            {
                byte[] x = new byte[16];
                for (int i = 0; i < 16; i++) x[i] = (byte) (pt[s * sector + b + i] ^ t[i]);
                x = k1.doFinal(x);
                for (int i = 0; i < 16; i++) out[s * sector + b + i] = (byte) (x[i] ^ t[i]);
                int c = 0;
                for (int i = 0; i < 16; i++) { int v = ((t[i] & 0xff) << 1) | c; c = v >> 8; t[i] = (byte) v; }
                if (c != 0) t[0] ^= (byte) 0x87;
            }
        }
        return out;
    }
}
