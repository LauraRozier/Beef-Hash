using System;

namespace beef_hash
{
	/* The MIT License

	   Copyright (C) 2012 Zilong Tan (eric.zltan@gmail.com)

	   Permission is hereby granted, free of charge, to any person
	   obtaining a copy of this software and associated documentation
	   files (the "Software"), to deal in the Software without
	   restriction, including without limitation the rights to use, copy,
	   modify, merge, publish, distribute, sublicense, and/or sell copies
	   of the Software, and to permit persons to whom the Software is
	   furnished to do so, subject to the following conditions:

	   The above copyright notice and this permission notice shall be
	   included in all copies or substantial portions of the Software.

	   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
	   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
	   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
	   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
	   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
	   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	   SOFTWARE.
	*/
	// https://github.com/rurban/smhasher/blob/master/fasthash.h
	abstract class FastHash
	{
		private const uint64 M_VAL = 0x880355F21E6D1965UL;

		// Compression function for Merkle-Damgard construction.
		// This function is generated using the framework provided.
		private static mixin mix(uint64 h) {				
			h ^= h >> 23;		
			h *= 0x2127599BF4325C37UL;	
			h ^ (h >> 47)
		}

		/**
		* fasthash64 - 64-bit implementation of fasthash
		* @buf:  data buffer
		* @len:  data size
		* @seed: the seed
		*/
		public static uint64 fasthash64(void* buf, uint len, uint64 seed)
		{
			uint64 *pos = (uint64*)buf;
			uint64 *end = pos + (len / 8);
			uint8*pos2;
			uint64 h = seed ^ (len * M_VAL);
			uint64 v;

			while (pos != end) {
				v  = *pos++;
				h ^= mix!(v);
				h *= M_VAL;
			}

			pos2 = (uint8*)pos;
			v = 0;

			switch(len & 7)
			{
				case 7: v ^= ((uint64)pos2[6]) << 48;
				case 6: v ^= ((uint64)pos2[5]) << 40;
				case 5: v ^= ((uint64)pos2[4]) << 32;
				case 4: v ^= ((uint64)pos2[3]) << 24;
				case 3: v ^= ((uint64)pos2[2]) << 16;
				case 2: v ^= ((uint64)pos2[1]) << 8;
				case 1: v ^= pos2[0]; h ^= mix!(v); h *= M_VAL;
			}

			return mix!(h);
		}

		/**
		* fasthash32 - 32-bit implementation of fasthash
		* @buf:  data buffer
		* @len:  data size
		* @seed: the seed
		*/
		public static uint32 fasthash32(void* buf, uint len, uint32 seed)
		{
			// the following trick converts the 64-bit hashcode to Fermat
			// residue, which shall retain information from both the higher
			// and lower parts of hashcode.
		    uint64 h = fasthash64(buf, len, seed);
			return (uint32)(h - (h >> 32));
		}
	}
}
