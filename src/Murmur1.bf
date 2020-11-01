using System;

namespace beef_hash
{
	/*-----------------------------------------------------------------------------------
	** MurmurHash was written by Austin Appleby, and is placed in the public
	** domain. The author hereby disclaims copyright to this source code.
	**
	** Note - This code makes a few assumptions about how your machine behaves -
	**
	** 1. We can read a 4-byte value from any address without crashing
	** 2. sizeof(int) == 4
	**
	** And it has a few limitations -
	**
	** 1. It will not work incrementally.
	** 2. It will not produce the same results on little-endian and big-endian machines.
	*/
	// https://github.com/rurban/smhasher/blob/master/MurmurHash1.cpp
	abstract class Murmur1
	{
		private const uint32 M_VAL = 0xC6A4A793U;
		private const int R_VAL = 16;

		public static uint32 Hash(void* key, int length, uint32 seed = 0)
		{
			uint32 len = (uint32)length;
  			uint32 h = seed ^ (len * M_VAL);

			//----------
			uint8* data = (uint8*)key;
			uint32 k;

			while (len >= 4) {
				k = *(uint32*)data;

				h += k;
				h *= M_VAL;
				h ^= h >> 16;

				data += 4;
				len -= 4;
			}

			//----------
			switch(len)
			{
				case 3: h += ((uint32)data[2]) << 16;
				case 2: h += ((uint32)data[1]) << 8;
				case 1: h += data[0]; h *= M_VAL; h ^= h >> R_VAL;
			}

			//----------
			h *= M_VAL;
			h ^= h >> 10;
			h *= M_VAL;
			return h ^ (h >> 17);
		}

		/*-------------------------------------------------------------------------------
		** MurmurHash1Aligned, by Austin Appleby
		**
		** Same algorithm as MurmurHash1, but only does aligned reads - should be safer
		** on certain platforms. 
		**
		** Performance should be equal to or better than the simple version.
		*/
		public static uint32 HashAligned(void* key, int length, uint32 seed = 0)
		{
			uint8* data = (uint8*)key;
			uint32 len = (uint32)length;
			uint32 h = seed ^ (len * M_VAL);
			uint32 align = (uint32)(*(uint64*)data & 3);

			if (align > 0 && len >= 4) {
				// Pre-load the temp registers
				uint32 t = 0, d = 0;

				switch(align)
				{
					case 1: t |= ((uint32)data[2]) << 16;
					case 2: t |= ((uint32)data[1]) << 8;
					case 3: t |= data[0];
				}

				t <<= (8 * align);

				data += 4 - align;
				len -= 4 - align;

				uint32 sl = 8 * (4 - align);
				uint32 sr = 8 * align;

				// Mix
				while (len >= 4) {
					d = *(uint32*)data;
					t = (t >> sr) | (d << sl);
					h += t;
					h *= M_VAL;
					h ^= h >> R_VAL;
					t = d;

					data += 4;
					len -= 4;
				}

				// Handle leftover data in temp registers
				uint32 pack = len < align ? len : align;
				d = 0;

				switch(pack)
				{
					case 3: d |= ((uint32)data[2]) << 16;
					case 2: d |= ((uint32)data[1]) << 8;
					case 1: d |= data[0];
					case 0: h += (t >> sr) | (d << sl); h *= M_VAL; h ^= h >> R_VAL;
				}

				data += pack;
				len -= pack;
			} else {
				while (len >= 4) {
					h += *(uint32*)data;
					h *= M_VAL;
					h ^= h >> R_VAL;

					data += 4;
					len -= 4;
				}
			}

			//----------
			// Handle tail bytes
			switch(len)
			{
				case 3: h += ((uint32)data[2]) << 16;
				case 2: h += ((uint32)data[1]) << 8;
				case 1: h += data[0]; h *= M_VAL; h ^= h >> R_VAL;
			}

			h *= M_VAL;
			h ^= h >> 10;
			h *= M_VAL;
			return h ^ (h >> 17);
		}

		public static mixin Hash(StringView val, uint32 seed = 0) { Hash(val.Ptr, val.Length * sizeof(char8), seed) }

		public static mixin Hash(int val, uint32 seed = 0)
		{
			var tmp = val;
			Hash(&tmp, sizeof(int), seed)
		}

		public static mixin Hash(uint val, uint32 seed = 0)
		{
			var tmp = val;
			Hash(&tmp, sizeof(uint), seed)
		}

		public static mixin HashAligned(StringView val, uint32 seed = 0) { HashAligned(val.Ptr, val.Length * sizeof(char8), seed) }

		public static mixin HashAligned(int val, uint32 seed = 0)
		{
			var tmp = val;
			HashAligned(&tmp, sizeof(int), seed)
		}

		public static mixin HashAligned(uint val, uint32 seed = 0)
		{
			var tmp = val;
			HashAligned(&tmp, sizeof(uint), seed)
		}
	}
}
