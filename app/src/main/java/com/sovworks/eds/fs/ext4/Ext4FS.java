package com.sovworks.eds.fs.ext4;

import android.os.ParcelFileDescriptor;

import com.sovworks.eds.fs.Directory;
import com.sovworks.eds.fs.FSRecord;
import com.sovworks.eds.fs.File;
import com.sovworks.eds.fs.FileSystem;
import com.sovworks.eds.fs.Path;
import com.sovworks.eds.fs.RandomAccessIO;
import com.sovworks.eds.fs.errors.FileSystemClosedException;
import com.sovworks.eds.fs.util.PathBase;
import com.sovworks.eds.fs.util.RandomAccessInputStream;
import com.sovworks.eds.fs.util.StringPathUtil;
import com.sovworks.eds.fs.util.Util;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * Read-only ext2/ext3/ext4 file system inside an EDS container, backed by the
 * native lwext4-based driver. Every mutating operation throws
 * {@link ReadOnlyException}.
 *
 * Thread safety: lwext4 is used without its OS lock hooks, and a volume can be force-closed
 * (e.g. USB drive unplugged) while other threads are reading. So every native call runs under
 * {@link #_lock}, and {@link #close} closes all open file handles before unmounting; nothing can
 * touch a native handle after it was freed.
 */
public class Ext4FS implements FileSystem
{
    public static class ReadOnlyException extends IOException
    {
        ReadOnlyException()
        {
            super("ext4 volumes are read-only in this version");
            // A UserException cause makes the UI show this text instead of a generic error.
            initCause(new com.sovworks.eds.android.errors.UserException(getMessage(), 0));
        }
    }

    private static final int SB_OFFSET = 1024, MAGIC_OFFSET = 0x38;

    /** True if the image has an ext2/3/4 superblock. */
    public static boolean isExt4Image(RandomAccessIO img) throws IOException
    {
        if (img.length() < SB_OFFSET + MAGIC_OFFSET + 2)
            return false;
        img.seek(SB_OFFSET + MAGIC_OFFSET);
        int lo = img.read(), hi = img.read();
        return lo == 0x53 && hi == 0xEF;
    }

    public static boolean isModuleInstalled()
    {
        return Ext4Native.isLoaded();
    }

    public Ext4FS(RandomAccessIO image) throws IOException
    {
        if (!Ext4Native.isLoaded())
            throw new IOException("ext4 native module is not available");
        _image = image;
        long h = Ext4Native.mount(image, image.length());
        if (h <= 0)
            throw new IOException(describe("Failed mounting ext4 volume", (int) -h));
        _vol = h;
    }

    @Override
    public Path getRootPath() throws IOException
    {
        return getPath("");
    }

    @Override
    public Path getPath(String pathString) throws IOException
    {
        return new Ext4Path(this, pathString == null ? "" : pathString);
    }

    @Override
    public void close(boolean force) throws IOException
    {
        synchronized (_lock)
        {
            if (_vol == 0)
                return;
            for (Ext4RandomAccessIO io : new ArrayList<>(_openFiles))
                io.closeLocked();
            _openFiles.clear();
            Ext4Native.umount(_vol);
            _vol = 0;
        }
    }

    @Override
    public boolean isClosed()
    {
        synchronized (_lock)
        {
            return _vol == 0;
        }
    }

    interface VolOp<T>
    {
        T run(long vol) throws IOException;
    }

    /** Runs a native operation on the mounted volume, serialized against close(). */
    <T> T withVol(VolOp<T> op) throws IOException
    {
        synchronized (_lock)
        {
            if (_vol == 0)
                throw new FileSystemClosedException();
            return op.run(_vol);
        }
    }

    long[] stat(String path) throws IOException
    {
        long[] out = new long[3];
        int r = withVol(v -> Ext4Native.stat(v, path, out));
        if (r == ENOENT || r == ENOTDIR)
            return null;
        if (r != 0)
            throw new IOException(describe("stat failed for " + path, r));
        return out;
    }

    static String describe(String msg, int errno)
    {
        switch (errno)
        {
            case ENOTSUP_LINUX:
            case ENOTSUP_BSD:
                return msg + ": the volume uses ext4 features this driver does not support " +
                        "(e.g. inline_data, casefold or fscrypt encryption)";
            default:
                return msg + " (errno " + errno + ")";
        }
    }

    private static final int ENOENT = 2, ENOTDIR = 20, ENOTSUP_LINUX = 95, ENOTSUP_BSD = 45;

    @SuppressWarnings("unused") // keep a strong ref: native code calls into it
    private final RandomAccessIO _image;
    private long _vol;
    final Object _lock = new Object();
    final Set<Ext4RandomAccessIO> _openFiles = new HashSet<>();

    // ------------------------------------------------------------------ path

    static class Ext4Path extends PathBase
    {
        Ext4Path(Ext4FS fs, String pathString)
        {
            this(fs, pathString, null);
        }

        /** stat: {type, size, mtime} delivered with a directory listing, or null. The volume is
         *  read-only and exclusively ours while mounted, so it can't go stale. */
        Ext4Path(Ext4FS fs, String pathString, long[] stat)
        {
            super(fs);
            _pathString = pathString;
            _stat = stat;
        }

        @Override public String getPathString() { return _pathString; }
        @Override public Ext4FS getFileSystem() { return (Ext4FS) super.getFileSystem(); }
        @Override public boolean exists() throws IOException { return stat() != null; }

        @Override
        public boolean isFile() throws IOException
        {
            long[] s = stat();
            return s != null && s[0] == Ext4Native.T_FILE;
        }

        @Override
        public boolean isDirectory() throws IOException
        {
            long[] s = stat();
            return s != null && s[0] == Ext4Native.T_DIR;
        }

        @Override public Directory getDirectory() { return new Ext4Directory(this); }
        @Override public File getFile() { return new Ext4File(this); }

        long[] stat() throws IOException
        {
            long[] s = _stat;
            if (s == null)
            {
                s = getFileSystem().stat(_pathString);
                _stat = s; // null (doesn't exist) is not cached
            }
            return s;
        }

        long[] statOrThrow() throws IOException
        {
            long[] s = stat();
            if (s == null)
                throw new FileNotFoundException(_pathString);
            return s;
        }

        private final String _pathString;
        private volatile long[] _stat;
    }

    // ---------------------------------------------------------------- records

    abstract static class Ext4Record implements FSRecord
    {
        Ext4Record(Ext4Path path) { _path = path; }

        @Override public Ext4Path getPath() { return _path; }
        @Override public String getName() { return _path.getPathUtil().getFileName(); }
        @Override public Date getLastModified() throws IOException { return new Date(_path.statOrThrow()[2] * 1000L); }
        @Override public void rename(String newName) throws IOException { throw new ReadOnlyException(); }
        @Override public void setLastModified(Date dt) throws IOException { throw new ReadOnlyException(); }
        @Override public void delete() throws IOException { throw new ReadOnlyException(); }
        @Override public void moveTo(Directory newParent) throws IOException { throw new ReadOnlyException(); }

        final Ext4Path _path;
    }

    static class Ext4Directory extends Ext4Record implements Directory
    {
        Ext4Directory(Ext4Path path) { super(path); }

        @Override public Directory createDirectory(String name) throws IOException { throw new ReadOnlyException(); }
        @Override public File createFile(String name) throws IOException { throw new ReadOnlyException(); }

        @Override
        public Contents list() throws IOException
        {
            Ext4FS fs = _path.getFileSystem();
            ArrayList<byte[]> raw = new ArrayList<>();
            ArrayList<long[]> stats = new ArrayList<>();
            long t0 = System.nanoTime();
            int r = fs.withVol(v -> Ext4Native.listStat(v, _path.getPathString(), raw, stats));
            com.sovworks.eds.android.Logger.debug(String.format("Ext4FS: listed %d entries of '%s' in %d ms (r=%d)",
                    raw.size(), _path.getPathString(), (System.nanoTime() - t0) / 1000000, r));
            if (r != 0)
                throw new IOException(describe("readdir failed for " + _path.getPathString(), r));
            if (stats.size() != raw.size())
                throw new IOException("readdir returned inconsistent results for " + _path.getPathString());
            final ArrayList<Path> paths = new ArrayList<>(raw.size());
            StringPathUtil cur = _path.getPathUtil();
            for (int i = 0; i < raw.size(); i++)
                paths.add(new Ext4Path(fs, cur.combine(new String(raw.get(i), StandardCharsets.UTF_8)).toString(), stats.get(i)));
            return new Contents()
            {
                @Override public void close() {}
                @Override public Iterator<Path> iterator() { return paths.iterator(); }
            };
        }

        @Override
        public long getTotalSpace() throws IOException
        {
            return space()[0];
        }

        @Override
        public long getFreeSpace() throws IOException
        {
            return space()[1];
        }

        private long[] space() throws IOException
        {
            long[] out = new long[2];
            int r = _path.getFileSystem().withVol(v -> Ext4Native.space(v, out));
            if (r != 0)
                throw new IOException(describe("statfs failed", r));
            return out;
        }
    }

    static class Ext4File extends Ext4Record implements File
    {
        Ext4File(Ext4Path path) { super(path); }

        @Override
        public InputStream getInputStream() throws IOException
        {
            return new RandomAccessInputStream(getRandomAccessIO(AccessMode.Read));
        }

        @Override public OutputStream getOutputStream() throws IOException { throw new ReadOnlyException(); }

        @Override
        public RandomAccessIO getRandomAccessIO(AccessMode accessMode) throws IOException
        {
            if (accessMode != AccessMode.Read)
                throw new ReadOnlyException();
            long[] s = _path.statOrThrow();
            if (s[0] != Ext4Native.T_FILE)
                throw new FileNotFoundException(_path.getPathString() + " is not a regular file");
            Ext4FS fs = _path.getFileSystem();
            return fs.withVol(v -> {
                long h = Ext4Native.open(v, _path.getPathString());
                if (h <= 0)
                    throw new IOException(describe("open failed for " + _path.getPathString(), (int) -h));
                Ext4RandomAccessIO io = new Ext4RandomAccessIO(fs, h);
                fs._openFiles.add(io);
                return io;
            });
        }

        @Override public long getSize() throws IOException { return _path.statOrThrow()[1]; }
        @Override public ParcelFileDescriptor getFileDescriptor(AccessMode accessMode) { return null; }

        @Override
        public void copyToOutputStream(OutputStream output, long offset, long count, ProgressInfo progressInfo) throws IOException
        {
            Util.copyFileToOutputStream(output, this, offset, count, progressInfo);
        }

        @Override
        public void copyFromInputStream(InputStream input, long offset, long count, ProgressInfo progressInfo) throws IOException
        {
            throw new ReadOnlyException();
        }
    }

    // -------------------------------------------------------------- file I/O

    static class Ext4RandomAccessIO implements RandomAccessIO
    {
        Ext4RandomAccessIO(Ext4FS fs, long handle)
        {
            _fs = fs;
            _handle = handle;
        }

        @Override
        public int read() throws IOException
        {
            byte[] b = new byte[1];
            return read(b, 0, 1) == 1 ? (b[0] & 0xFF) : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException
        {
            if (len == 0)
                return 0;
            synchronized (_fs._lock)
            {
                check();
                int n = Ext4Native.pread(_handle, _pos, b, off, len);
                if (n < 0)
                    throw new IOException(describe("read failed", -n));
                if (n == 0)
                    return -1;
                _pos += n;
                return n;
            }
        }

        @Override public void seek(long position) throws IOException
        {
            if (position < 0)
                throw new IOException("negative seek");
            synchronized (_fs._lock)
            {
                _pos = position;
            }
        }

        @Override public long getFilePointer() { synchronized (_fs._lock) { return _pos; } }

        @Override public long length() throws IOException
        {
            synchronized (_fs._lock)
            {
                check();
                return Ext4Native.fsize(_handle);
            }
        }

        @Override public void write(int b) throws IOException { throw new ReadOnlyException(); }
        @Override public void write(byte[] b, int off, int len) throws IOException { throw new ReadOnlyException(); }
        @Override public void flush() {}
        @Override public void setLength(long newLength) throws IOException { throw new ReadOnlyException(); }

        @Override
        public void close()
        {
            synchronized (_fs._lock)
            {
                closeLocked();
                _fs._openFiles.remove(this);
            }
        }

        /** Caller holds _fs._lock; the volume is still mounted if _fs._vol != 0. */
        void closeLocked()
        {
            if (_handle != 0)
            {
                if (_fs._vol != 0)
                    Ext4Native.close(_handle);
                _handle = 0;
            }
        }

        private void check() throws IOException
        {
            if (_fs._vol == 0)
                throw new FileSystemClosedException();
            if (_handle == 0)
                throw new IOException("file is closed");
        }

        private final Ext4FS _fs;
        private long _handle;
        private long _pos;
    }
}
