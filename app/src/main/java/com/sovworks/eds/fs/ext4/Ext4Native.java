package com.sovworks.eds.fs.ext4;

import com.sovworks.eds.fs.RandomAccessIO;

import java.util.Collection;

/** JNI entry points of libedsext4 (app/src/main/native/ext4). Read-only. */
final class Ext4Native
{
    static final int T_OTHER = 0, T_FILE = 1, T_DIR = 2;

    static boolean isLoaded()
    {
        return LOADED;
    }

    static native int getVersion();
    /** @return volume handle (&gt;0) or -errno */
    static native long mount(RandomAccessIO io, long size);
    static native void umount(long vol);
    /** out = {type, size, mtimeSeconds}; @return 0 or errno */
    static native int stat(long vol, String path, long[] out);
    /** Adds raw UTF-8 names (byte[]) to names; @return 0 or errno */
    static native int list(long vol, String path, Collection<byte[]> names);
    /** @return file handle (&gt;0) or -errno */
    static native long open(long vol, String path);
    /** @return bytes read, 0 at EOF, or -errno */
    static native int pread(long file, long pos, byte[] buf, int off, int len);
    static native long fsize(long file);
    static native void close(long file);
    /** out = {total, free}; @return 0 or errno */
    static native int space(long vol, long[] out);

    private static final boolean LOADED;
    static
    {
        boolean ok;
        try
        {
            System.loadLibrary("edsext4");
            ok = getVersion() >= 1;
        }
        catch (Throwable e)
        {
            ok = false;
        }
        LOADED = ok;
    }

    private Ext4Native() {}
}
