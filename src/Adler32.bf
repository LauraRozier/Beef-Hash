using System;

namespace beef_hash
{
	abstract class Adler32
	{
		private const uint32 BASE = 65521; // largest prime smaller than 2^16

		private static mixin Hash(char8* data, int len, uint32 adler, ref uint32 h1, ref uint32 h2)
		{
			h1 = adler & 0xffff;
			h2 = (adler >> 16) & 0xffff;

			for (var i = 0; i < len; i++) {
				h1 += (uint8)data[i];
				h2 += h1;
			}
		}

		public static uint32 Hash(char8* data, int len, uint32 adler = 1)
		{
			uint32 h1 = ?, h2 = ?;
			Hash!(data, len, adler, ref h1, ref h2);
			return ((h2 % BASE) << 16) + (h1 % BASE);
		}

		// Reverse order for smaller numbers
		public static uint32 HashReverse(char8* data, int len, uint32 adler = 1)
		{
			uint32 h1 = ?, h2 = ?;
			Hash!(data, len, adler, ref h1, ref h2);
			return (h2 % BASE) + ((h1 % BASE) << 16);
		}
	}
}
