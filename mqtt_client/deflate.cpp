#include "stdafx.h"
#include "deflate.h"
#include "zlib.h"
#include "zconf.h"
#include "zutil.h"
#include <stdio.h>


#pragma comment(lib,"zlibstat.lib")

int ZEXPORT compress2(
	Bytef *dest,
	uLongf *destLen,
	const Bytef *source,
	uLong sourceLen,
	int level)
{
	z_stream stream;
	int err;

	stream.next_in = (Bytef*)source;
	stream.avail_in = (uInt)sourceLen;
#ifdef MAXSEG_64K
	/* Check for source > 64K on 16-bit machine: */
	if ((uLong)stream.avail_in != sourceLen)
	{
		printf("(uLong)stream.avail_in != sourceLen)  \r\n");
		return Z_BUF_ERROR;
	}
#endif
	stream.next_out = dest;
	stream.avail_out = (uInt)*destLen;
	if ((uLong)stream.avail_out != *destLen)
	{
		printf("((uLong)stream.avail_out != *destLen)  \r\n");
		return Z_BUF_ERROR;
	}

	stream.zalloc = (alloc_func)0;
	stream.zfree = (free_func)0;
	stream.opaque = (voidpf)0;

	err = deflateInit(&stream, level);
	if (err != Z_OK) return err;

	err = deflate(&stream, Z_FINISH);
	if (err != Z_STREAM_END) {
		deflateEnd(&stream);
		printf("err :%d  deflate(&stream, Z_FINISH) \r\n", err);
		return err == Z_OK ? Z_BUF_ERROR : err;
	}
	*destLen = stream.total_out;

	err = deflateEnd(&stream);
	return err;
}

int ZEXPORT compress(
	Bytef *dest,
	uLongf *destLen,
	const Bytef *source,
	uLong sourceLen)
{
	return compress2(dest, destLen, source, sourceLen, Z_DEFAULT_COMPRESSION);

}


uLong ZEXPORT compressBound(
	uLong sourceLen)
{
	return sourceLen + (sourceLen >> 12) + (sourceLen >> 14) +
		(sourceLen >> 25) + 13;

}



int ZEXPORT uncompress(
	Bytef *dest,
	uLongf *destLen,
	const Bytef *source,
	uLong sourceLen)
{
	z_stream stream;
	int err;

	stream.next_in = (Bytef*)source;
	stream.avail_in = (uInt)sourceLen;
	/* Check for source > 64K on 16-bit machine: */
	if ((uLong)stream.avail_in != sourceLen) return Z_BUF_ERROR;

	stream.next_out = dest;
	stream.avail_out = (uInt)*destLen;
	if ((uLong)stream.avail_out != *destLen) return Z_BUF_ERROR;

	stream.zalloc = (alloc_func)0;
	stream.zfree = (free_func)0;

	err = inflateInit(&stream);
	if (err != Z_OK) return err;

	err = inflate(&stream, Z_FINISH);
	if (err != Z_STREAM_END) {
		inflateEnd(&stream);
		if (err == Z_NEED_DICT || (err == Z_BUF_ERROR && stream.avail_in == 0))
			return Z_DATA_ERROR;
		return err;
	}
	*destLen = stream.total_out;

	err = inflateEnd(&stream);
	return err;
}