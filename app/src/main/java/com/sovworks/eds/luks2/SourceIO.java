package com.sovworks.eds.luks2;

import com.sovworks.eds.fs.RandomAccessIO;

import java.io.IOException;

/** Read-only {@link RandomAccessIO} view of a {@link Luks2Header.Source}; every write method throws. */
public final class SourceIO implements RandomAccessIO
{
    private final Luks2Header.Source src;
    private long pos;

    public SourceIO(Luks2Header.Source src)
    {
        this.src = src;
    }

    @Override
    public synchronized int read() throws IOException
    {
        byte[] b = new byte[1];
        return read(b, 0, 1) == 1 ? b[0] & 0xff : -1;
    }

    @Override
    public synchronized int read(byte[] b, int off, int len) throws IOException
    {
        long n = Math.min(len, src.size() - pos);
        if (n <= 0)
            return len == 0 ? 0 : -1;
        src.readFully(pos, b, off, (int) n);
        pos += n;
        return (int) n;
    }

    @Override
    public synchronized void seek(long position) throws IOException
    {
        if (position < 0)
            throw new IOException("negative seek");
        pos = position;
    }

    @Override public synchronized long getFilePointer() { return pos; }
    @Override public long length() throws IOException { return src.size(); }
    @Override public void write(int b) throws IOException { throw new IOException("read-only"); }
    @Override public void write(byte[] b, int off, int len) throws IOException { throw new IOException("read-only"); }
    @Override public void flush() { }
    @Override public void setLength(long newLength) throws IOException { throw new IOException("read-only"); }
    @Override public void close() { }
}
