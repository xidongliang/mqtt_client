#ifndef __DEFLATE_H__
#define __DEFLATE_H__
#include "zlib.h"
#include "zconf.h"
#include "zutil.h"



int ZEXPORT compress2(
	Bytef *dest,
	uLongf *destLen,
	const Bytef *source,
	uLong sourceLen,
	int level);

int ZEXPORT compress(
	Bytef *dest,
	uLongf *destLen,
	const Bytef *source,
	uLong sourceLen);


uLong ZEXPORT compressBound(
uLong sourceLen);



int ZEXPORT uncompress(
Bytef *dest,
uLongf *destLen,
const Bytef *source,
uLong sourceLen);

#endif