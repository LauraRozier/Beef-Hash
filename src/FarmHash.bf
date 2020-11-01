using System;

namespace beef_hash
{
	/* Copyright (c) 2014 Google, Inc.
	**
	** Permission is hereby granted, free of charge, to any person obtaining a copy
	** of this software and associated documentation files (the "Software"), to deal
	** in the Software without restriction, including without limitation the rights
	** to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	** copies of the Software, and to permit persons to whom the Software is
	** furnished to do so, subject to the following conditions:
	**
	** The above copyright notice and this permission notice shall be included in
	** all copies or substantial portions of the Software.
	**
	** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	** THE SOFTWARE.
	**
	** FarmHash, by Geoff Pike
	**
	**
	** http://code.google.com/p/farmhash/
	**
	** This file provides a few functions for hashing strings and other
	** data.  All of them are high-quality functions in the sense that
	** they do well on standard tests such as Austin Appleby's SMHasher.
	** They're also fast.  FarmHash is the successor to CityHash.
	**
	** Functions in the FarmHash family are not suitable for cryptography.
	**
	** WARNING: This code has been only lightly tested on big-endian platforms!
	** It is known to work well on little-endian platforms that have a small penalty
	** for unaligned reads, such as current Intel and AMD moderate-to-high-end CPUs.
	** It should work on all 32-bit and 64-bit platforms that allow unaligned reads;
	** bug reports are welcome.
	**
	** By the way, for some hash functions, given strings a and b, the hash
	** of a+b is easily derived from the hashes of a and b.  This property
	** doesn't hold for any hash functions in this file.
	*/
	// https://github.com/rurban/smhasher/blob/master/farmhash-c.c
	abstract class FarmHash
	{
		// const uint64 K_MUL = 0x9DDFEA08EB382D69UL;
		const uint64 MHB_K_MUL = 0x9DDFEA08EB382D69UL;

		public struct uint128_c_t {
			public uint64 a;
			public uint64 b;
		}

		public static mixin uint128_c_t_low64(uint128_c_t x) { x.a }
		public static mixin uint128_c_t_high64(uint128_c_t x) { x.b }

		private static mixin make_uint128_c_t(uint64 lo, uint64 hi) {
			uint128_c_t x = .(){ a = lo, b = hi };
			x
		}

#if BF_LITTLE_ENDIAN
		private static mixin uint32_in_expected_order(uint32 x) { x }
		private static mixin uint64_in_expected_order(uint64 x) { x }
#else
		private static mixin uint32_in_expected_order(uint32 x) { bswap32(x) }
		private static mixin uint64_in_expected_order(uint64 x) { bswap64(x) }
#endif

		private static mixin PERMUTE3(uint32* a, uint32* b, uint32* c)
		{
			swap32!(a, b);
			swap32!(a, c);
		}

		[Inline]
		private static uint32 bswap32(uint32 x) {
			uint32 y = x;

			for (uint32 i = 0; i < sizeof(uint32) >> 1; i++) {
				uint32 d = sizeof(uint32) - i - 1;

				uint32 mh = ((uint32)0xFF) << (d << 3);
				uint32 ml = ((uint32)0xFF) << (i << 3);

				uint32 h = x & mh;
				uint32 l = x & ml;

				uint64 t = (l << ((d - i) << 3)) | (h >> ((d - i) << 3));

				y = (uint32)(t | (y & ~(mh | ml)));
			}

			return y;
		}

		[Inline]
		private static uint64 bswap64(uint64 x) {
			uint64 y = x;

			for (uint64 i = 0; i < sizeof(uint64) >> 1; i++) {
				uint64 d = sizeof(uint64) - i - 1;

				uint64 mh = ((uint64)0xFF) << (d << 3);
				uint64 ml = ((uint64)0xFF) << (i << 3);

				uint64 h = x & mh;
				uint64 l = x & ml;

				uint64 t = (l << ((d - i) << 3)) | (h >> ((d - i) << 3));

				y = t | (y & ~(mh | ml));
			}

			return y;
		}

		private static mixin fetch32(char8* p) {
			uint32 result = *(uint32*)p;
			uint32_in_expected_order!(result)
		}

		private static mixin fetch64(char8* p) {
			uint64 result = *(uint64*)p;
			uint64_in_expected_order!(result)
		}

		private static mixin swap32(uint32* a, uint32* b) {
			uint32 t;
			
			t = *a;
			*a = *b;
			*b = t;
		}

		private static mixin swap64(uint64* a, uint64* b) {
			uint64 t;

			t = *a;
			*a = *b;
			*b = t;
		}

		private static mixin ror32(uint32 val, uint shift) {
			// Avoid shifting by 32: doing so yields an undefined result.
			shift == 0 ? val : (val >> shift) | (val << (32 - shift))
		}

		private static mixin ror64(uint64 val, uint shift) {
			// Avoid shifting by 64: doing so yields an undefined result.
			shift == 0 ? val : (val >> shift) | (val << (64 - shift))
		}

		// Building blocks for hash functions

		// Some primes between 2^63 and 2^64 for various uses.
		private const uint64 k0 = 0xc3a5c85c97cb3127UL;
		private const uint64 k1 = 0xb492b66fbe98f273UL;
		private const uint64 k2 = 0x9ae16a3b2f90404fUL;

		// Magic numbers for 32-bit hashing.  Copied from Murmur3.
		private const uint32 c1 = 0xCC9E2D51L;
		private const uint32 c2 = 0x1B873593L;

		// A 32-bit to 32-bit integer hash copied from Murmur3.
		private static mixin fmix(uint32 h) {
			h ^= h >> 16;
			h *= 0x85EBCA6BU;
			h ^= h >> 13;
			h *= 0xC2b2AE35U;
			h ^= h >> 16;
			return h;
		}

		private static mixin smix(uint64 val) {
			val ^ (val >> 47)
		}

		private static mixin mur(uint32 a, uint32 h) {
			// Helper from Murmur3 for combining two 32-bit values.
			a *= c1;
			a = ror32!(a, 17);
			a *= c2;
			h ^= a;
			h = ror32!(h, 19);
			h * 5 + 0xE6546B64U
		}

		private static mixin debug_tweak32(uint32 val) {
			uint32 x = val;
#if !NDEBUG
			x = ~bswap32(x * c1);
#endif
			x
		}

		private static mixin debug_tweak64(uint64 val) {
			uint64 x = val;
#if !NDEBUG
			x = ~bswap64(x * k1);
#endif
			x
		}

		private static mixin debug_tweak128(uint128_c_t val) {
			uint128_c_t x = val;
#if !NDEBUG
			uint64 y = debug_tweak64!(uint128_c_t_low64!(x));
			uint64 z = debug_tweak64!(uint128_c_t_high64!(x));
			y += z;
			z += y;
			x = make_uint128_c_t!(y, z * k1);
#endif
			x
		}

		private static mixin farmhash_len_16(uint64 u, uint64 v) {
			farmhash128_to_64!(make_uint128_c_t!(u, v))
		}

		private static mixin farmhash_len_16_mul(uint64 u, uint64 v, uint64 mul) {
			// Murmur-inspired hashing.
			uint64 a = (u ^ v) * mul;
			a ^= (a >> 47);
			uint64 b = (v ^ a) * mul;
			b ^= (b >> 47);
			b * mul
		}

		// farmhash na

		[Inline]
		private static uint64 farmhash_na_len_0_to_16(char8*s, uint len) {
			if (len >= 8) {
				uint64 mul = k2 + len * 2;
				uint64 a = fetch64!(s) + k2;
				uint64 b = fetch64!(s + len - 8);
				uint64 c = ror64!(b, 37) * mul + a;
				uint64 d = (ror64!(a, 25) + b) * mul;
				return farmhash_len_16_mul!(c, d, mul);
			}

			if (len >= 4) {
				uint64 mul = k2 + len * 2;
				uint64 a = fetch32!(s);
				return farmhash_len_16_mul!(len + (a << 3), fetch32!(s + len - 4), mul);
			}

			if (len > 0) {
				uint8 a = (uint8)s[0];
				uint8 b = (uint8)s[len >> 1];
				uint8 c = (uint8)s[len - 1];
				uint32 y = (uint32)a + ((uint32)b << 8);
				uint32 z = (uint32)(len + ((uint32)c << 2));
				return smix!(y * k2 ^ z * k0) * k2;
			}

			return k2;
		}

		// This probably works well for 16-byte strings as well, but it may be overkill
		// in that case.
		[Inline]
		private static uint64 farmhash_na_len_17_to_32(char8* s, uint len) {
			uint64 mul = k2 + len * 2;
			uint64 a = fetch64!(s) * k1;
			uint64 b = fetch64!(s + 8);
			uint64 c = fetch64!(s + len - 8) * mul;
			uint64 d = fetch64!(s + len - 16) * k2;
			return farmhash_len_16_mul!(ror64!(a + b, 43) + ror64!(c, 30) + d, a + ror64!(b + k2, 18) + c, mul);
		}
		
		// Return a 16-byte hash for 48 bytes.  Quick and dirty.
		// Callers do best to use "random-looking" values for a and b.
		[Inline]
		private static uint128_c_t weak_farmhash_na_len_32_with_seeds_vals(uint64 w, uint64 x, uint64 y, uint64 z, uint64 a, uint64 b) {
			uint64 al = a, bl = b;
			al += w;
			bl = ror64!(bl + al + z, 21);
			uint64 c = al;
			al += x;
			al += y;
			bl += ror64!(al, 44);
			return make_uint128_c_t!(al + z, bl + c);
		}
		
		// Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
		private static mixin weak_farmhash_na_len_32_with_seeds(char8* s, uint64 a, uint64 b) {
			weak_farmhash_na_len_32_with_seeds_vals(fetch64!(s), fetch64!(s + 8), fetch64!(s + 16), fetch64!(s + 24), a, b)
		}
		
		// Return an 8-byte hash for 33 to 64 bytes.
		[Inline]
		private static uint64 farmhash_na_len_33_to_64(char8* s, uint len) {
			uint64 mul = k2 + len * 2;
			uint64 a = fetch64!(s) * k2;
			uint64 b = fetch64!(s + 8);
			uint64 c = fetch64!(s + len - 8) * mul;
			uint64 d = fetch64!(s + len - 16) * k2;
			uint64 y = ror64!(a + b, 43) + ror64!(c, 30) + d;
			uint64 z = farmhash_len_16_mul!(y, a + ror64!(b + k2, 18) + c, mul);
			uint64 e = fetch64!(s + 16) * mul;
			uint64 f = fetch64!(s + 24);
			uint64 g = (y + fetch64!(s + len - 32)) * mul;
			uint64 h = (z + fetch64!(s + len - 24)) * mul;
			return farmhash_len_16_mul!(ror64!(e + f, 43) + ror64!(g, 30) + h, e + ror64!(f + a, 18) + g, mul);
		}

		private static uint64 farmhash64_na(char8* str, uint len) {
			const uint64 seed = 81;
			char8* s = str;

			if (len <= 32) {
				if (len <= 16) {
					return farmhash_na_len_0_to_16(s, len);
				} else {
					return farmhash_na_len_17_to_32(s, len);
				}
			} else if (len <= 64) {
				return farmhash_na_len_33_to_64(s, len);
			}
			
			// For strings over 64 bytes we loop.  Internal state consists of 56 bytes: v, w, x, y, and z.
			uint64 x = seed;
			// seed =                   81 (0x              51)
			// k1 =   13011662864482103923 (0xb492b66fbe98f273)
			//                         113 (0x              71)
			//         2480279821605975764 (0x226BB95B4E64B6D4) according to http://calc.penjee.com/?s=EAaLDIBLFFPLOIHPBGCcGAk
			//         2480279821605975926 (0x226BB95B4E64B776) according to Ms Calc <- lol
			//         2480279821605975764 (0x226BB95B4E64B6D4) according to C++ (https://onlinegdb.com/ByWeS5odD)
			uint64 y = 0x226BB95B4E64B6D4UL;// seed * k1 + 113;
			uint64 z = smix!(y * k2 + 113) * k2;
			uint128_c_t v = make_uint128_c_t!(0, 0);
			uint128_c_t w = make_uint128_c_t!(0, 0);
			x = x * k2 + fetch64!(s);
			
			// Set end so that after the loop we have 1 to 64 bytes left to process.
			char8* end = s + ((len - 1) / 64) * 64;
			char8* last64 = end + ((len - 1) & 63) - 63;
			// assert(s + len - 64 == last64);
			
			repeat {
				x = ror64!(x + y + v.a + fetch64!(s + 8), 37) * k1;
				y = ror64!(y + v.b + fetch64!(s + 48), 42) * k1;
				x ^= w.b;
				y += v.a + fetch64!(s + 40);
				z = ror64!(z + w.a, 33) * k1;
				v = weak_farmhash_na_len_32_with_seeds!(s, v.b * k1, x + w.a);
				w = weak_farmhash_na_len_32_with_seeds!(s + 32, z + w.b, y + fetch64!(s + 16));
				swap64!(&z, &x);
				s += 64;
			} while (s != end);

			uint64 mul = k1 + ((z & 0xff) << 1);
			// Make s point to the last 64 bytes of input.
			s = last64;
			w.a += ((len - 1) & 63);
			v.a += w.a;
			w.a += v.a;
			x = ror64!(x + y + v.a + fetch64!(s + 8), 37) * mul;
			y = ror64!(y + v.b + fetch64!(s + 48), 42) * mul;
			x ^= w.b * 9;
			y += v.a * 9 + fetch64!(s + 40);
			z = ror64!(z + w.a, 33) * mul;
			v = weak_farmhash_na_len_32_with_seeds!(s, v.b * mul, x + w.a);
			w = weak_farmhash_na_len_32_with_seeds!(s + 32, z + w.b, y + fetch64!(s + 16));
			swap64!(&z, &x);
			return farmhash_len_16_mul!(farmhash_len_16_mul!(v.a, w.a, mul) + smix!(y) * k0 + z, farmhash_len_16_mul!(v.b, w.b, mul) + x, mul);
		}

		private static mixin farmhash64_na_with_seeds(char8* s, uint len, uint64 seed0, uint64 seed1) {
			farmhash_len_16!(farmhash64_na(s, len) - seed0, seed1)
		}

		private static mixin farmhash64_na_with_seed(char8* s, uint len, uint64 seed) {
			farmhash64_na_with_seeds!(s, len, k2, seed)
		}

		// BASIC STRING HASHING
		
		// Hash function for a byte array.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		public static uint farmhash(char8* s, uint len)
		{
			return 0;
		}
		
		// Hash function for a byte array.  Most useful in 32-bit binaries.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		public static uint32 farmhash32(char8* s, uint len)
		{
			return 0;
		}
		
		// Hash function for a byte array.  For convenience, a 32-bit seed is also
		// hashed into the result.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		public static uint32 farmhash32_with_seed(char8* s, uint len, uint32 seed)
		{
			return 0;
		}
		
		// Hash 128 input bits down to 64 bits of output.
		// Hash function for a byte array.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		public static uint64 farmhash64(char8* s, uint len)
		{
			return 0;
		}
		
		// Hash function for a byte array.  For convenience, a 64-bit seed is also
		// hashed into the result.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		public static uint64 farmhash64_with_seed(char8* s, uint len, uint64 seed)
		{
			return 0;
		}
		
		// Hash function for a byte array.  For convenience, two seeds are also
		// hashed into the result.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		public static uint64 farmhash64_with_seeds(char8* s, uint len, uint64 seed0, uint64 seed1)
		{
			return 0;
		}
		
		// Hash function for a byte array.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		public static uint128_c_t farmhash128(char8* s, uint len)
		{
			uint128_c_t res = .();
			return res;
		}
		// Hash function for a byte array.  For convenience, a 128-bit seed is also
		// hashed into the result.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		public static uint128_c_t farmhash128_with_seed(char8* s, uint len, uint128_c_t seed)
		{
			uint128_c_t res = .();
			return res;
		}
		
		// BASIC NON-STRING HASHING
		
		// This is intended to be a reasonably good hash function.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		public static mixin farmhash128_to_64(uint128_c_t x) {
			// Murmur-inspired hashing.
			uint64 a = (uint128_c_t_low64!(x) ^ uint128_c_t_high64!(x)) * MHB_K_MUL;
			a ^= (a >> 47);
			uint64 b = (uint128_c_t_high64!(x) ^ a) * MHB_K_MUL;
			b ^= (b >> 47);
			b * MHB_K_MUL
		}
		
		// FINGERPRINTING (i.e., good, portable, forever-fixed hash functions)
		
		// Fingerprint function for a byte array.  Most useful in 32-bit binaries.
		public static uint32 farmhash_fingerprint32(char8* s, uint len)
		{
			return 0;
		}
		
		// Fingerprint function for a byte array.
		public static uint64 farmhash_fingerprint64(char8* s, uint len)
		{
			return 0;
		}
		
		// Fingerprint function for a byte array.
		public static uint128_c_t farmhash_fingerprint128(char8* s, uint len)
		{
			uint128_c_t res = .();
			return res;
		}
		
		// This is intended to be a good fingerprinting primitive.
		// See below for more overloads.
		public static mixin farmhash_fingerprint_uint128_c_t(uint128_c_t x) {
			// Murmur-inspired hashing.
			uint64 a = (uint128_c_t_low64!(x) ^ uint128_c_t_high64!(x)) * MHB_K_MUL;
			a ^= (a >> 47);
			uint64 b = (uint128_c_t_high64!(x) ^ a) * MHB_K_MUL;
			b ^= (b >> 44);
			b *= MHB_K_MUL;
			b ^= (b >> 41);
			b * MHB_K_MUL
		}
		
		// This is intended to be a good fingerprinting primitive.
		public static mixin farmhash_fingerprint_uint64_t(uint64 x) {
			// Murmur-inspired hashing.
			uint64 b = x * MHB_K_MUL;
			b ^= (b >> 44);
			b *= MHB_K_MUL;
			b ^= (b >> 41);
			b * MHB_K_MUL
		}
	}
}
