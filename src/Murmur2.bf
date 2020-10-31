using System;

namespace beef_hash
{
	/*-----------------------------------------------------------------------------------
	** MurmurHash2 was written by Austin Appleby, and is placed in the public  domain.
	** The author hereby disclaims copyright to this source code.
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
	class Murmur2
	{
		// 'm' and 'r' are mixing constants generated offline.
		// They're not really 'magic', they just happen to work well.
		private const uint32 M_VAL = 0x5BD1E995;
		private const int R_VAL = 24;

		private uint32 m_hash;
		private uint32 m_tail;
		private uint32 m_count;
		private uint32 m_size;

		private static mixin mmix(ref uint32 h, ref uint32 k, uint32 m, uint32 r)
		{
			k *= m;
			k ^= k >> r;
			k *= m;
			h *= m;
			h ^= k;
		}

		/*-------------------------------------------------------------------------------
		** CMurmurHash2A, by Austin Appleby
		**
		** This is a sample implementation of MurmurHash2A designed to work incrementally
		**
		** Usage - 
		**
		** Murmur2 hasher
		** hasher.Begin(seed);
		** hasher.Add(data1, size1);
		** hasher.Add(data2, size2);
		** ...
		** hasher.Add(dataN, sizeN);
		** uint32 hash = hasher.End()
		*/
		public void Begin(uint32 seed = 0)
		{
			m_hash  = seed;
			m_tail  = 0;
			m_count = 0;
			m_size  = 0;
		}

		public void Add(uint8* data, int length)
		{
			uint8* lData = data;
			uint32 len = (uint32)length;
			m_size += len;

			MixTail(ref lData, ref len);

			while (len >= 4) {
				uint32 k = *(uint32*)lData;

				mmix!(ref m_hash, ref k, M_VAL, R_VAL);

				lData += 4;
				len -= 4;
			}

			MixTail(ref lData, ref len);
		}

		public uint32 End()
		{
			mmix!(ref m_hash, ref m_tail, M_VAL, R_VAL);
			mmix!(ref m_hash, ref m_size, M_VAL, R_VAL);

			m_hash ^= m_hash >> 13;
			m_hash *= M_VAL;
			m_hash ^= m_hash >> 15;

			return m_hash;
		}

		private void MixTail(ref uint8* data, ref uint32 len)
		{
			while (len > 0 && ((len < 4) || m_count > 0)) {
				m_tail |= (*data++) << (m_count * 8);

				m_count++;
				len--;

				if (m_count == 4) {
					mmix!(ref m_hash, ref m_tail, M_VAL, R_VAL);
					m_tail = 0;
					m_count = 0;
				}
			}
		}

		// https://github.com/rurban/smhasher/blob/master/MurmurHash2.cpp
		public static uint32 Hash(void* key, int length, uint32 seed) {
			uint32 len = (uint32)length;
			// Initialize the hash to a 'random' value
			uint32 h = seed ^ len;

			// Mix 4 bytes at a time into the hash
			uint8* data = (uint8*)key;

			while (len >= 4) {
				uint32 k = *(uint32*)data;

				k *= M_VAL;
				k ^= k >> R_VAL;
				k *= M_VAL;

				h *= M_VAL;
				h ^= k;

				data += 4;
				len -= 4;
			}

			// Handle the last few bytes of the input array
			switch(len)
			{
				case 3: h ^= ((uint32)data[2]) << 16;
				case 2: h ^= ((uint32)data[1]) << 8;
				case 1: h ^= data[0]; h *= M_VAL;
			}

			// Do a few final mixes of the hash to ensure the last few
			// bytes are well-incorporated.
			h ^= h >> 13;
			h *= M_VAL;
			return h ^ (h >> 15);
		}

		/*-------------------------------------------------------------------------------
		** MurmurHash2A, by Austin Appleby
		**
		** This is a variant of MurmurHash2 modified to use the Merkle-Damgard 
		** construction. Bulk speed should be identical to Murmur2, small-key speed  will
		** be 10%-20% slower due to the added overhead at the end of the hash.
		**
		** This variant fixes a minor issue where null keys were more likely to collide
		** with each other than expected, and also makes the function more amenable to
		** incremental implementations.
		*/
		public static uint32 HashA(void* key, int length, uint32 seed)
		{
			uint32 len = (uint32)length;
			uint32 l = len;

			uint8* data = (uint8*)key;

			uint32 h = seed;

			while (len >= 4) {
				uint32 k = *(uint32*)data;

				mmix!(ref h, ref k, M_VAL, R_VAL);

				data += 4;
				len -= 4;
			}

			uint32 t = 0;

			switch(len)
			{
				case 3: t ^= ((uint32)data[2]) << 16;
				case 2: t ^= ((uint32)data[1]) << 8;
				case 1: t ^= data[0];
			}

			mmix!(ref h, ref t, M_VAL, R_VAL);
			mmix!(ref h, ref l, M_VAL, R_VAL);

			h ^= h >> 13;
			h *= M_VAL;
			return h ^ (h >> 15);
		}

		/*-------------------------------------------------------------------------------
		** MurmurHash2, 64-bit versions, by Austin Appleby
		**
		** The same caveats as 32-bit MurmurHash2 apply here - beware of alignment and
		** endian-ness issues if used across multiple platforms.
		**
		** 64-bit hash for 64-bit platforms
		*/
		public static uint64 Hash64A(void* key, int length, uint64 seed)
		{
			const uint64 m = 0xC6A4A7935BD1E995;
			const int r = 47;

			uint32 len = (uint32)length;
			uint64 h = seed ^ (len * m);

			uint64* data = (uint64*)key;
			uint64* end = data + (len / 8);

			while (data != end) {
				uint64 k = *data++;

				k *= m; 
				k ^= k >> r; 
				k *= m; 

				h ^= k;
				h *= m; 
			}

			uint8* data2 = (uint8*)data;

			switch(len & 7)
			{
				case 7: h ^= ((uint64)data2[6]) << 48;
				case 6: h ^= ((uint64)data2[5]) << 40;
				case 5: h ^= ((uint64)data2[4]) << 32;
				case 4: h ^= ((uint64)data2[3]) << 24;
				case 3: h ^= ((uint64)data2[2]) << 16;
				case 2: h ^= ((uint64)data2[1]) << 8;
				case 1: h ^= ((uint64)data2[0]); h *= m;
			}

			h ^= h >> r;
			h *= m;
			return h ^ (h >> r);
		}

		// 64-bit hash for 32-bit platforms
		public static uint64 Hash64B(void* key, int length, uint64 seed)
		{
			uint32 len = (uint32)length;
			uint32 h1 = ((uint32)seed) ^ len;
			uint32 h2 = ((uint32)(seed >> 32));

			uint32* data = (uint32*)key;

			while (len >= 8) {
				uint32 k1 = *data++;
				k1 *= M_VAL;
				k1 ^= k1 >> R_VAL;
				k1 *= M_VAL;
				h1 *= M_VAL;
				h1 ^= k1;
				len -= 4;

				uint32 k2 = *data++;
				k2 *= M_VAL;
				k2 ^= k2 >> R_VAL;
				k2 *= M_VAL;
				h2 *= M_VAL;
				h2 ^= k2;
				len -= 4;
			}

			if (len >= 4) {
				uint32 k1 = *data++;
				k1 *= M_VAL;
				k1 ^= k1 >> R_VAL;
				k1 *= M_VAL;
				h1 *= M_VAL;
				h1 ^= k1;
				len -= 4;
			}

			switch(len)
			{
				case 3: h2 ^= ((uint32)((uint8*)data)[2]) << 16;
				case 2: h2 ^= ((uint32)((uint8*)data)[1]) << 8;
				case 1: h2 ^= ((uint8*)data)[0]; h2 *= M_VAL;
			}

			h1 ^= h2 >> 18;
			h1 *= M_VAL;

			h2 ^= h1 >> 22;
			h2 *= M_VAL;

			h1 ^= h2 >> 17;
			h1 *= M_VAL;

			h2 ^= h1 >> 19;
			h2 *= M_VAL;

			return (((uint64)h1) << 32) | h2;
		}

		/*-------------------------------------------------------------------------------
		** MurmurHashNeutral2, by Austin Appleby
		**
		** Same as MurmurHash2, but endian- and alignment-neutral. Half the speed though,
		** alas.
		*/
		public static uint32 HashNeutral(void* key, int length, uint32 seed)
		{
			uint32 len = (uint32)length;
			uint32 h = seed ^ len;

			uint8* data = (uint8*)key;

			while (len >= 4) {
				uint32 k;

				k = data[0];
				k |= ((uint32)data[1]) << 8;
				k |= ((uint32)data[2]) << 16;
				k |= ((uint32)data[3]) << 24;

				k *= M_VAL; 
				k ^= k >> R_VAL; 
				k *= M_VAL;

				h *= M_VAL;
				h ^= k;

				data += 4;
				len -= 4;
			}

			switch(len)
			{
				case 3: h ^= ((uint32)data[2]) << 16;
				case 2: h ^= ((uint32)data[1]) << 8;
				case 1: h ^= data[0]; h *= M_VAL;
			}

			h ^= h >> 13;
			h *= M_VAL;
			return h ^ (h >> 15);
		}

		/*-------------------------------------------------------------------------------
		** MurmurHashAligned2, by Austin Appleby
		**
		** Same algorithm as MurmurHash2, but only does aligned reads - should be safer
		** on certain platforms. 
		**
		** Performance will be lower than MurmurHash2
		*/
		public static uint32 HashAligned(void* key, int length, uint32 seed)
		{
			uint32 len = (uint32)length;
			uint8* data = (uint8*)key;

			uint32 h = seed ^ len;
			uint32 align = (uint32)(*(uint64*)data & 3);

			if (align > 0 && (len >= 4)) {
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

				int sl = 8 * (4 - align);
				int sr = 8 * align;

				// Mix
				while (len >= 4) {
					d = *(uint32*)data;
					t = (t >> sr) | (d << sl);

					uint32 k = t;

					mmix!(ref h, ref k, M_VAL, R_VAL);

					t = d;

					data += 4;
					len -= 4;
				}

				// Handle leftover data in temp registers
				d = 0;

				if (len >= align) {
					switch(align)
					{
						case 3: d |= ((uint32)data[2]) << 16;
						case 2: d |= ((uint32)data[1]) << 8;
						case 1: d |= data[0];
					}

					uint32 k = (t >> sr) | (d << sl);
					mmix!(ref h, ref k, M_VAL, R_VAL);

					data += align;
					len -= align;

					//----------
					// Handle tail bytes
					switch(len)
					{
						case 3: h ^= ((uint32)data[2]) << 16;
						case 2: h ^= ((uint32)data[1]) << 8;
						case 1: h ^= data[0];
						h *= M_VAL;
					}
				} else {
					switch(len)
					{
						case 3: d |= ((uint32)data[2]) << 16;
						case 2: d |= ((uint32)data[1]) << 8;
						case 1: d |= data[0];
						case 0: h ^= (t >> sr) | (d << sl); h *= M_VAL;
					}
				}

				h ^= h >> 13;
				h *= M_VAL;
				return h ^ (h >> 15);
			} else {
				while (len >= 4) {
					uint32 k = *(uint32*)data;

					mmix!(ref h, ref k, M_VAL, R_VAL);

					data += 4;
					len -= 4;
				}

				//----------
				// Handle tail bytes
				switch(len)
				{
					case 3: h ^= ((uint32)data[2]) << 16;
					case 2: h ^= ((uint32)data[1]) << 8;
					case 1: h ^= data[0]; h *= M_VAL;
				}

				h ^= h >> 13;
				h *= M_VAL;
				return h ^ (h >> 15);
			}
		}

		public static mixin Hash(StringView val, uint32 seed = 0)
		{
			Hash(val.Ptr, val.Length, seed)
		}

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

		public static mixin HashA(StringView val, uint32 seed = 0)
		{
			HashA(val.Ptr, val.Length, seed)
		}

		public static mixin HashA(int val, uint32 seed = 0)
		{
			var tmp = val;
			HashA(&tmp, sizeof(int), seed)
		}

		public static mixin HashA(uint val, uint32 seed = 0)
		{
			var tmp = val;
			HashA(&tmp, sizeof(uint), seed)
		}

		public static mixin Hash64A(StringView val, uint32 seed = 0)
		{
			Hash64A(val.Ptr, val.Length, seed)
		}

		public static mixin Hash64A(int val, uint32 seed = 0)
		{
			var tmp = val;
			Hash64A(&tmp, sizeof(int), seed)
		}

		public static mixin Hash64A(uint val, uint32 seed = 0)
		{
			var tmp = val;
			Hash64A(&tmp, sizeof(uint), seed)
		}

		public static mixin Hash64B(StringView val, uint32 seed = 0)
		{
			Hash64B(val.Ptr, val.Length, seed)
		}

		public static mixin Hash64B(int val, uint32 seed = 0)
		{
			var tmp = val;
			Hash64B(&tmp, sizeof(int), seed)
		}

		public static mixin Hash64B(uint val, uint32 seed = 0)
		{
			var tmp = val;
			Hash64B(&tmp, sizeof(uint), seed)
		}

		public static mixin HashAligned(StringView val, uint32 seed = 0)
		{
			HashAligned(val.Ptr, val.Length, seed)
		}

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

		public static mixin HashNeutral(StringView val, uint32 seed = 0)
		{
			HashNeutral(val.Ptr, val.Length, seed)
		}

		public static mixin HashNeutral(int val, uint32 seed = 0)
		{
			var tmp = val;
			HashNeutral(&tmp, sizeof(int), seed)
		}

		public static mixin HashNeutral(uint val, uint32 seed = 0)
		{
			var tmp = val;
			HashNeutral(&tmp, sizeof(uint), seed)
		}
	}
}
