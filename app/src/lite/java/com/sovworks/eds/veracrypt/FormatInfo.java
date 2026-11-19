package com.sovworks.eds.veracrypt;

import com.sovworks.eds.container.VolumeLayout;


public class FormatInfo extends com.sovworks.eds.truecrypt.FormatInfo 
{

	public static final String FORMAT_NAME = "VeraCrypt";

	@Override
	public String getFormatName()
	{
		return FORMAT_NAME;
	}

	@Override
	public VolumeLayout getVolumeLayout()
	{
		return new com.sovworks.eds.veracrypt.VolumeLayout();
	}

	@Override
	public int getOpeningPriority()
	{		
		return 3;
	}

	/** VeraCrypt 1.24+ accepts 128-byte (UTF-8) passwords for non-system volumes. */
	@Override
	public int getMaxPasswordLength()
	{
		return 128;
	}

	/** Earlier VeraCrypt and EDS versions used at most 64 bytes. */
	@Override
	public int getLegacyMaxPasswordLength()
	{
		return 64;
	}

	@Override
	public boolean hasCustomKDFIterationsSupport()
	{
		return true;
	}

}
