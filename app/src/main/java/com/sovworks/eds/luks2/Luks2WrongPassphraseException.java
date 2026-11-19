package com.sovworks.eds.luks2;

/** No keyslot could be opened with the given passphrase. */
public class Luks2WrongPassphraseException extends Luks2Exception
{
    public Luks2WrongPassphraseException() { super("no keyslot matches this passphrase"); }
}
