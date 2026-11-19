package com.sovworks.eds.luks2;

import java.io.IOException;

/** Malformed, unsupported or unsafe-to-open LUKS2 volume. */
public class Luks2Exception extends IOException
{
    public Luks2Exception(String msg) { super(msg); }
}
