namespace beef_hash
{
	/*
	** author: Jon Maiga, 2020-08-03, jonkagstrom.com, @jonkagstrom
	** license: CC0 license
	*/
	// https://github.com/jonmaiga/mx3/blob/master/mx3.h
	abstract class Mx3
	{
		private const uint64 C = 0xBEA225F9EB34556DUL;

		private static mixin mix(uint64 val)
		{
			uint64 x = val;
			x ^= x >> 32;
			x *= C;
			x ^= x >> 29;
			x *= C;
			x ^= x >> 32;
			x *= C;
			x ^ (x >> 29)
		}

		private static mixin mix_stream(uint64 hash, uint64 val)
		{
			uint64 h = hash, x = val;
			x *= C;
			x ^= (x >> 57) ^ (x >> 43);
			x *= C;
			h += x;
			h * C
		}

		public static uint64 hash(void* buf, uint length, uint64 seed)
		{
			uint len = length;
			uint64* buf64 = (uint64*)buf;
			uint8* tail = (uint8*)(buf64 + len / 8);

			uint64 h = seed ^ len;

			while (len >= 32) {
				len -= 32;
				h = mix_stream!(h, *buf64++);
				h = mix_stream!(h, *buf64++);
				h = mix_stream!(h, *buf64++);
				h = mix_stream!(h, *buf64++);
			}

			while (len >= 8) {
				len -= 8;
				h = mix_stream!(h, *buf64++);
			}

			uint64 v = 0;

			switch(len & 7)
			{
				case 7: v |= (uint64)(tail[6]) << 48; fallthrough;
				case 6: v |= (uint64)(tail[5]) << 40; fallthrough;
				case 5: v |= (uint64)(tail[4]) << 32; fallthrough;
				case 4: v |= (uint64)(tail[3]) << 24; fallthrough;
				case 3: v |= (uint64)(tail[2]) << 16; fallthrough;
				case 2: v |= (uint64)(tail[1]) << 8; fallthrough;
				case 1: h = mix_stream!(h, v | tail[0]);
			}

			return mix!(h);
		}
	}
}
