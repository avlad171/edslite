package com.sovworks.eds.luks2;

/** JNI entry points of libedsluks (app/src/main/native/luks). */
final class Luks2Native
{
    static final int ARGON2I = 1, ARGON2ID = 2;

    static native int getVersion();
    /** @return 0 or an Argon2 error code (&lt;0) */
    /** Called from native code between Argon2 slices; return false to cancel. */
    interface Progress
    {
        boolean onProgress(int done, int total);
    }

    /** Returned by argon2 when Progress.onProgress returned false (memory is wiped and freed). */
    static final int ARGON2_CANCELLED = -100;

    static native int argon2(int type, byte[] password, byte[] salt, int t, int memoryKiB, int lanes, byte[] out,
                             Progress progress);
    static native String argon2Error(int code);
    /** @return opaque AES-XTS context, or 0 on bad key size. Caller wipes key. */
    static native long xtsNew(byte[] key);
    static native void xtsFree(long handle);
    /** Decrypt in place, plain64 IV starting at iv0, +1 per sector. @return 0 or errno */
    static native int xtsDecrypt(long handle, byte[] buf, int off, int len, int sectorSize, long iv0);

    private static volatile boolean loaded;

    static synchronized void ensureLoaded()
    {
        if (!loaded)
        {
            System.loadLibrary("edsluks");
            if (getVersion() < 1)
                throw new UnsatisfiedLinkError("incompatible edsluks");
            loaded = true;
        }
    }

    private Luks2Native() {}
}
