package com.sovworks.eds.container;

import com.sovworks.eds.exceptions.ApplicationException;
import com.sovworks.eds.fs.FileSystemInfo;
import com.sovworks.eds.fs.RandomAccessIO;

import java.io.IOException;

public interface ContainerFormatInfo
{
	String getFormatName();
	VolumeLayout getVolumeLayout();
	boolean hasHiddenContainerSupport();
	boolean hasKeyfilesSupport();
	boolean hasCustomKDFIterationsSupport();
	int getMaxPasswordLength();
	/** A shorter limit older versions truncated passwords to, tried as a fallback; 0 if none. */
	default int getLegacyMaxPasswordLength() { return 0; }
	VolumeLayout getHiddenVolumeLayout();
	void formatContainer(RandomAccessIO io, VolumeLayout layout, FileSystemInfo fsInfo) throws IOException, ApplicationException;
	int getOpeningPriority();
}
