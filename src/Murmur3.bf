using System;

namespace beef_hash
{
	/*-----------------------------------------------------------------------------------
	** MurmurHash3 was written by Austin Appleby, and is placed in the public  domain.
	** The author hereby disclaims copyright to this source code.
	**
	** Note - The x86 and x64 versions do _not_ produce the same results, as the
	** algorithms are optimized for their respective platforms. You can still compile and
	** run any of them on any platform, but your performance with the non-native version
	** will be less than optimal.
	*/
	// https://github.com/rurban/smhasher/blob/master/MurmurHash3.cpp
	abstract class Murmur3
	{
		private static mixin rotl32(uint32 x, int8 r) { (x << r) | (x >> (32 - r)) }

		private static mixin rotl64(uint64 x, int8 r) { (x << r) | (x >> (64 - r)) }

		/*-------------------------------------------------------------------------------
		** Block read - if your platform needs to do endian-swapping or can only handle
		** aligned reads, do the conversion here
		*/
		private static mixin getblock32(uint32* p, int i) { p[i] }

		private static mixin getblock64(uint64* p, int i) { p[i] }

		/*-------------------------------------------------------------------------------
		** Finalization mix - force all bits of a hash block to avalanche
		*/
		private static mixin fmix32(uint32 h)
		{
			h ^= h >> 16;
			h *= 0x85EBCA6BU;
			h ^= h >> 13;
			h *= 0xC2B2AE35U;
			h ^ (h >> 16)
		}

		private static mixin fmix64(uint64 h)
		{
			h ^= h >> 33;
			h *= 0xFF51AFD7ED558CCDUL;
			h ^= h >> 33;
			h *= 0xC4CEB9FE1A85EC53UL;
			h ^ (h >> 33)
		}
		
		public static uint32 Hash_32(void* key, int length, uint32 seed)
		{
			const uint32 c1 = 0xCC9E2D51U;
			const uint32 c2 = 0x1B873593U;

			uint32 len = (uint32)length;
			uint8* data = (uint8*)key;
			int nblocks = length / 4;
			uint32 h = seed;

			//----------
			// body
			uint32* blocks = (uint32*)data;

			for (int i = 0; i < nblocks; i++) {
				uint32 k = getblock32!(blocks, i);

				k *= c1;
				k = rotl32!(k, 15);
				k *= c2;

				h ^= k;
				h = rotl32!(h, 13); 
				h = h * 5 + 0xE6546B64U;
			}

			//----------
			// tail
			uint8* tail = (uint8*)(data + nblocks * 4);
			uint32 k = 0;

			switch(len & 3)
			{
				case 3: k ^= ((uint32)tail[2]) << 16; fallthrough;
				case 2: k ^= ((uint32)tail[1]) << 8; fallthrough;
				case 1: {
					k ^= tail[0];
					k *= c1;
					k = rotl32!(k, 15);
					k *= c2;
					h ^= k;
				}
			}

			//----------
			// finalization
			h ^= len;
			return fmix32!(h);
		}

		public static uint8* Hash_x86_128(void* key, int length, uint32 seed)
		{
			const uint32 c1 = 0x239B961BU; 
			const uint32 c2 = 0xAB0E9789U;
			const uint32 c3 = 0x38B34AE5U; 
			const uint32 c4 = 0xA1E38B93U;

			uint32 len = (uint32)length;
			uint8 * data = (uint8*)key;
			int nblocks = length / 16;

			uint32 h1 = seed;
			uint32 h2 = seed;
			uint32 h3 = seed;
			uint32 h4 = seed;

			//----------
			// body
			uint32 * blocks = (uint32*)(data);

			for (int i = 0; i < nblocks; i++) {
				uint32 k1 = getblock32!(blocks,i * 4);
				uint32 k2 = getblock32!(blocks,i * 4 + 1);
				uint32 k3 = getblock32!(blocks,i * 4 + 2);
				uint32 k4 = getblock32!(blocks,i * 4 + 3);

				k1 *= c1;
				k1 = rotl32!(k1, 15);
				k1 *= c2;
				h1 ^= k1;

				h1 = rotl32!(h1, 19);
				h1 += h2;
				h1 = h1 * 5 + 0x561CCD1BU;

				k2 *= c2;
				k2 = rotl32!(k2, 16);
				k2 *= c3;
				h2 ^= k2;

				h2 = rotl32!(h2, 17);
				h2 += h3;
				h2 = h2 * 5 + 0x0BCAA747U;

				k3 *= c3;
				k3 = rotl32!(k3, 17);
				k3 *= c4;
				h3 ^= k3;

				h3 = rotl32!(h3, 15);
				h3 += h4;
				h3 = h3 * 5 + 0x96CD1C35U;

				k4 *= c4;
				k4 = rotl32!(k4, 18);
				k4 *= c1;
				h4 ^= k4;

				h4 = rotl32!(h4, 13);
				h4 += h1;
				h4 = h4 * 5 + 0x32AC3B17U;
			}

			//----------
			// tail
			uint8* tail = (uint8*)(data + nblocks * 16);

			uint32 k1 = 0;
			uint32 k2 = 0;
			uint32 k3 = 0;
			uint32 k4 = 0;

			switch(len & 15)
			{
				case 15: k4 ^= ((uint32)tail[14]) << 16; fallthrough;
				case 14: k4 ^= ((uint32)tail[13]) << 8; fallthrough;
				case 13: k4 ^= ((uint32)tail[12]) << 0; k4 *= c4; k4 = rotl32!(k4, 18); k4 *= c1; h4 ^= k4; fallthrough;
				case 12: k3 ^= ((uint32)tail[11]) << 24; fallthrough;
				case 11: k3 ^= ((uint32)tail[10]) << 16; fallthrough;
				case 10: k3 ^= ((uint32)tail[ 9]) << 8; fallthrough;
				case  9: k3 ^= ((uint32)tail[ 8]) << 0; k3 *= c3; k3 = rotl32!(k3, 17); k3 *= c4; h3 ^= k3; fallthrough;
				case  8: k2 ^= ((uint32)tail[ 7]) << 24; fallthrough;
				case  7: k2 ^= ((uint32)tail[ 6]) << 16; fallthrough;
				case  6: k2 ^= ((uint32)tail[ 5]) << 8; fallthrough;
				case  5: k2 ^= ((uint32)tail[ 4]) << 0; k2 *= c2; k2 = rotl32!(k2, 16); k2 *= c3; h2 ^= k2; fallthrough;
				case  4: k1 ^= ((uint32)tail[ 3]) << 24; fallthrough;
				case  3: k1 ^= ((uint32)tail[ 2]) << 16; fallthrough;
				case  2: k1 ^= ((uint32)tail[ 1]) << 8; fallthrough;
				case  1: k1 ^= ((uint32)tail[ 0]) << 0; k1 *= c1; k1 = rotl32!(k1, 15); k1 *= c2; h1 ^= k1;
			}

			//----------
			// finalization
			h1 ^= len;
			h2 ^= len;
			h3 ^= len;
			h4 ^= len;

			h1 += h2;
			h1 += h3;
			h1 += h4;
			h2 += h1;
			h3 += h1;
			h4 += h1;

			h1 = fmix32!(h1);
			h2 = fmix32!(h2);
			h3 = fmix32!(h3);
			h4 = fmix32!(h4);

			h1 += h2;
			h1 += h3;
			h1 += h4;
			h2 += h1;
			h3 += h1;
			h4 += h1;

			return (uint8*)&uint32[4](h1, h2, h3, h4);
		}

		[Inline]
		public static void Hash_x86_128(void* key, int length, uint32 seed, String outStr)
		{
			uint32* tmp = (uint32*)Hash_x86_128(key, length, seed);

			tmp[0].ToString(outStr, "X", null);
			tmp[1].ToString(outStr, "X", null);
			tmp[2].ToString(outStr, "X", null);
			tmp[3].ToString(outStr, "X", null);
		}

		public static uint8* Hash_x64_128(void* key, int length, uint32 seed)
		{
			const uint64 c1 = 0x87C37B91114253D5UL;
			const uint64 c2 = 0x4CF5AD432745937FUL;

			uint32 len = (uint32)length;
			uint8* data = (uint8*)key;
			int nblocks = length / 16;

			uint64 h1 = seed;
			uint64 h2 = seed;

			//----------
			// body
			uint64* blocks = (uint64*)data;

			for (int i = 0; i < nblocks; i++) {
				uint64 k1 = getblock64!(blocks, i * 2);
				uint64 k2 = getblock64!(blocks, i * 2 + 1);

				k1 *= c1;
				k1 = rotl64!(k1, 31);
				k1 *= c2;
				h1 ^= k1;

				h1 = rotl64!(h1, 27);
				h1 += h2;
				h1 = h1 * 5 + 0x52DCE729U;

				k2 *= c2;
				k2 = rotl64!(k2, 33);
				k2 *= c1;
				h2 ^= k2;

				h2 = rotl64!(h2, 31);
				h2 += h1;
				h2 = h2 * 5 + 0x38495AB5U;
			}

			//----------
			// tail
			uint8 * tail = (uint8*)(data + nblocks * 16);

			uint64 k1 = 0;
			uint64 k2 = 0;

			switch(len & 15)
			{
				case 15: k2 ^= ((uint64)tail[14]) << 48; fallthrough;
				case 14: k2 ^= ((uint64)tail[13]) << 40; fallthrough;
				case 13: k2 ^= ((uint64)tail[12]) << 32; fallthrough;
				case 12: k2 ^= ((uint64)tail[11]) << 24; fallthrough;
				case 11: k2 ^= ((uint64)tail[10]) << 16; fallthrough;
				case 10: k2 ^= ((uint64)tail[ 9]) << 8; fallthrough;
				case  9: k2 ^= ((uint64)tail[ 8]) << 0; k2 *= c2; k2 = rotl64!(k2, 33); k2 *= c1; h2 ^= k2; fallthrough;
				case  8: k1 ^= ((uint64)tail[ 7]) << 56; fallthrough;
				case  7: k1 ^= ((uint64)tail[ 6]) << 48; fallthrough;
				case  6: k1 ^= ((uint64)tail[ 5]) << 40; fallthrough;
				case  5: k1 ^= ((uint64)tail[ 4]) << 32; fallthrough;
				case  4: k1 ^= ((uint64)tail[ 3]) << 24; fallthrough;
				case  3: k1 ^= ((uint64)tail[ 2]) << 16; fallthrough;
				case  2: k1 ^= ((uint64)tail[ 1]) << 8; fallthrough;
				case  1: k1 ^= ((uint64)tail[ 0]) << 0; k1 *= c1; k1 = rotl64!(k1, 31); k1 *= c2; h1 ^= k1;
			}

			//----------
			// finalization
			h1 ^= len;
			h2 ^= len;

			h1 += h2;
			h2 += h1;

			h1 = fmix64!(h1);
			h2 = fmix64!(h2);

			h1 += h2;
			h2 += h1;

			return (uint8*)&uint64[2](h1, h2);
		}

		[Inline]
		public static void Hash_x64_128(void* key, int length, uint32 seed, String outStr)
		{
			uint64* tmp = (uint64*)Hash_x86_128(key, length, seed);

			tmp[0].ToString(outStr, "X", null);
			tmp[1].ToString(outStr, "X", null);
		}

		public static mixin Hash_128(StringView val, String outStr, uint32 seed = 0)
		{
			if (outStr == null) {
				outStr = scope:: .();
			} else {
				outStr.Clear();
			}

#if BF_64_BIT
			Hash_x64_128(val.Ptr, val.Length, seed, outStr)
#else
			Hash_x86_128(val.Ptr, val.Length * sizeof(char8), seed, outStr)
#endif
		}

		public static mixin Hash_128(int val, String outStr, uint32 seed = 0)
		{
			if (outStr == null) {
				outStr = scope:: .();
			} else {
				outStr.Clear();
			}

			var tmp = val;
#if BF_64_BIT
			Hash_x64_128(&tmp, sizeof(int), seed, outStr)
#else
			Hash_x86_128(&tmp, sizeof(int), seed, outStr)
#endif
		}

		public static mixin Hash_128(uint val, String outStr, uint32 seed = 0)
		{
			if (outStr == null) {
				outStr = scope:: .();
			} else {
				outStr.Clear();
			}

			var tmp = val;
#if BF_64_BIT
			Hash_x64_128(&tmp, sizeof(uint), seed, outStr)
#else
			Hash_x86_128(&tmp, sizeof(uint), seed, outStr)
#endif
		}

		public static mixin Hash_32(StringView val, uint32 seed = 0) { Hash_32(val.Ptr, val.Length * sizeof(char8), seed) }

		public static mixin Hash_32(int val, uint32 seed = 0)
		{
			var tmp = val;
			Hash_32(&tmp, sizeof(int), seed)
		}

		public static mixin Hash_32(uint val, uint32 seed = 0)
		{
			var tmp = val;
			Hash_32(&tmp, sizeof(uint), seed)
		}
	}
}
