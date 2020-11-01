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

		public struct uint128_c_t
		{
			public uint64 a;
			public uint64 b;
		}

		public static mixin uint128_c_t_low64(uint128_c_t x) { x.a }
		public static mixin uint128_c_t_high64(uint128_c_t x) { x.b }

		public static mixin make_uint128_c_t(uint64 lo, uint64 hi) {
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
		private static uint32 bswap32(uint32 x)
		{
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
		private static uint64 bswap64(uint64 x)
		{
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

		private static mixin fetch32(char8* p)
		{
			uint32 result = *(uint32*)p;
			uint32_in_expected_order!(result)
		}

		private static mixin fetch64(char8* p)
		{
			uint64 result = *(uint64*)p;
			uint64_in_expected_order!(result)
		}

#if CAN_USE_SSSE3 || CAN_USE_SSE41 || CAN_USE_SSE42 || CAN_USE_AESNI || CAN_USE_AVX
		private static mixin fetch128(char8* s) { _mm_loadu_si128((__m128i*)s) }
#endif

		private static mixin swap32(uint32* a, uint32* b)
		{
			uint32 t;
			
			t = *a;
			*a = *b;
			*b = t;
		}

		private static mixin swap64(uint64* a, uint64* b)
		{
			uint64 t;

			t = *a;
			*a = *b;
			*b = t;
		}

#if CAN_USE_SSSE3 || CAN_USE_SSE41 || CAN_USE_SSE42 || CAN_USE_AESNI || CAN_USE_AVX
		private static mixin swap128(__m128i* a, __m128i* b)
		{
			__m128i t;
			
			t = *a;
			*a = *b;
			*b = t;
		}
#endif

		private static mixin ror32(uint32 val, uint shift)
		{
			// Avoid shifting by 32: doing so yields an undefined result.
			shift == 0 ? val : (val >> shift) | (val << (32 - shift))
		}

		private static mixin ror64(uint64 val, uint shift)
		{
			// Avoid shifting by 64: doing so yields an undefined result.
			shift == 0 ? val : (val >> shift) | (val << (64 - shift))
		}

		// Helpers for data-parallel operations (1x 128 bits or 2x64 or 4x32 or 8x16).
#if CAN_USE_SSSE3 || CAN_USE_SSE41 || CAN_USE_SSE42 || CAN_USE_AESNI || CAN_USE_AVX
		private static mixin add64x2(__m128i x, __m128i y) { _mm_add_epi64(x, y) }
		private static mixin add32x4(__m128i x, __m128i y) { _mm_add_epi32(x, y) }

		private static mixin xor128(__m128i x, __m128i y) { _mm_xor_si128(x, y) }
		private static mixin or128(__m128i x, __m128i y) { _mm_or_si128(x, y) }

		private static mixin mul32x4_5(__m128i x) { add32x4!(x, _mm_slli_epi32(x, 2)) }

		private static mixin rol32x4(__m128i x, int c) { or128!(_mm_slli_epi32(x, c), _mm_srli_epi32(x, 32 - c)) }

		private static mixin rol32x4_17(__m128i x) { rol32x4!(x, 17) }
		private static mixin rol32x4_19(__m128i x) { rol32x4!(x, 19) }

		private static mixin shuf32x4_0_3_2_1(__m128i x) { _mm_shuffle_epi32(x, (0 << 6) + (3 << 4) + (2 << 2) + (1 << 0)) }
#endif

#if CAN_USE_SSSE3
		private static mixin shuf8x16(__m128i x, __m128i y) { _mm_shuffle_epi8(y, x) }
#endif

#if CAN_USE_SSE41
		private static mixin mul32x4(__m128i x, __m128i y) { _mm_mullo_epi32(x, y) }
		
		private static mixin murk(__m128i a, __m128i b, __m128i c, __m128i d, __m128i e)
		{
			add32x4!(e, mul32x4_5!(rol32x4_19!(xor128!(mul32x4!(d, rol32x4_17!(mul32x4!(c, a))), b))))
		}
#endif

		// Building blocks for hash functions

		// Some primes between 2^63 and 2^64 for various uses.
		private const uint64 k0 = 0xC3A5C85C97CB3127UL;
		private const uint64 k1 = 0xB492B66FBE98F273UL;
		private const uint64 k2 = 0x9AE16A3B2F90404fUL;

		// Magic numbers for 32-bit hashing.  Copied from Murmur3.
		private const uint32 c1 = 0xCC9E2D51L;
		private const uint32 c2 = 0x1B873593L;

		// A 32-bit to 32-bit integer hash copied from Murmur3.
		[Inline]
		private static uint32 fmix(uint32 hash)
		{
			uint32 h = hash;
			h ^= h >> 16;
			h *= 0x85EBCA6BU;
			h ^= h >> 13;
			h *= 0xC2b2AE35U;
			return h ^ h >> 16;
		}

		[Inline]
		private static uint64 smix(uint64 val) { return val ^ (val >> 47); }

		[Inline]
		private static uint32 mur(uint32 x, uint32 hash)
		{
			uint32 a = x, h = hash;
			// Helper from Murmur3 for combining two 32-bit values.
			a *= c1;
			a = ror32!(a, 17);
			a *= c2;
			h ^= a;
			h = ror32!(h, 19);
			return h * 5 + 0xE6546B64U;
		}

		private static mixin debug_tweak32(uint32 val)
		{
			uint32 x = val;
#if !NDEBUG
			x = ~bswap32(x * c1);
#endif
			x
		}

		private static mixin debug_tweak64(uint64 val)
		{
			uint64 x = val;
#if !NDEBUG
			x = ~bswap64(x * k1);
#endif
			x
		}

		private static mixin debug_tweak128(uint128_c_t val)
		{
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

		private static mixin farmhash_len_16(uint64 u, uint64 v) { farmhash128_to_64!(make_uint128_c_t!(u, v)) }

		private static mixin farmhash_len_16_mul(uint64 u, uint64 v, uint64 mul)
		{
			// Murmur-inspired hashing.
			uint64 a = (u ^ v) * mul;
			a ^= (a >> 47);
			uint64 b = (v ^ a) * mul;
			b ^= (b >> 47);
			b * mul
		}

		// farmhash na
		[Inline]
		private static uint64 farmhash_na_len_0_to_16(char8* s, int length)
		{
			uint32 len = (uint32)length;

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
				return smix(y * k2 ^ z * k0) * k2;
			}

			return k2;
		}

		// This probably works well for 16-byte strings as well, but it may be overkill in that case.
		[Inline]
		private static uint64 farmhash_na_len_17_to_32(char8* s, int length)
		{
			uint32 len = (uint32)length;
			uint64 mul = k2 + len * 2;
			uint64 a = fetch64!(s) * k1;
			uint64 b = fetch64!(s + 8);
			uint64 c = fetch64!(s + len - 8) * mul;
			uint64 d = fetch64!(s + len - 16) * k2;
			return farmhash_len_16_mul!(ror64!(a + b, 43) + ror64!(c, 30) + d, a + ror64!(b + k2, 18) + c, mul);
		}
		
		/* Return a 16-byte hash for 48 bytes.  Quick and dirty.
		** Callers do best to use "random-looking" values for a and b.
		*/
		[Inline]
		private static uint128_c_t weak_farmhash_na_len_32_with_seeds_vals(uint64 w, uint64 x, uint64 y, uint64 z, uint64 a, uint64 b)
		{
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
		private static mixin weak_farmhash_na_len_32_with_seeds(char8* s, uint64 a, uint64 b)
		{
			weak_farmhash_na_len_32_with_seeds_vals(fetch64!(s), fetch64!(s + 8), fetch64!(s + 16), fetch64!(s + 24), a, b)
		}
		
		// Return an 8-byte hash for 33 to 64 bytes.
		[Inline]
		private static uint64 farmhash_na_len_33_to_64(char8* s, int length)
		{
			uint32 len = (uint32)length;
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

		private static uint64 farmhash64_na(char8* str, int length)
		{
			const uint64 seed = 81;
			uint32 len = (uint32)length;
			char8* s = str;

			if (len <= 32) {
				return len <= 16 ? farmhash_na_len_0_to_16(s, length) : farmhash_na_len_17_to_32(s, length);
			} else if (len <= 64) {
				return farmhash_na_len_33_to_64(s, length);
			}
			
			// For strings over 64 bytes we loop.  Internal state consists of 56 bytes: v, w, x, y, and z.
			uint64 x = seed;

			/* seed =                   81 (0x              51)
			** k1 =   13011662864482103923 (0xb492b66fbe98f273)
			**                         113 (0x              71)
			**         2480279821605975764 (0x226BB95B4E64B6D4) according to http://calc.penjee.com/?s=EAaLDIBLFFPLOIHPBGCcGAk
			**         2480279821605975926 (0x226BB95B4E64B776) according to Ms Calc <- lol
			**         2480279821605975764 (0x226BB95B4E64B6D4) according to C++ (https://onlinegdb.com/ByWeS5odD)
			*/
			//uint64 y = seed * k1 + 113; // Result out of range for type 'uint64'
#if BF_LITTLE_ENDIAN
			//uint64 y = 0x51 * 0xb492b66fbe98f273UL + 0x71;
			uint64 y = 0x226BB95B4E64B6D4UL;
#else
			//uint54 y = 0x51 * 0x73f298be6fb692b4UL + 0x71;
			uint64 y = 0xAFC2544158C46B65UL; // Maybe? just byte-swapped the int and calculated with LE C++
#endif

			uint64 z = smix(y * k2 + 113) * k2;
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
			return farmhash_len_16_mul!(farmhash_len_16_mul!(v.a, w.a, mul) + smix(y) * k0 + z, farmhash_len_16_mul!(v.b, w.b, mul) + x, mul);
		}

		[Inline]
		private static uint64 farmhash64_na_with_seeds(char8* s, int len, uint64 seed0, uint64 seed1)
		{
			return farmhash_len_16!(farmhash64_na(s, len) - seed0, seed1);
		}

		[Inline]
		private static uint64 farmhash64_na_with_seed(char8* s, int len, uint64 seed)
		{
			return farmhash64_na_with_seeds(s, len, k2, seed);
		}

		// farmhash uo
		[Inline]
		private static uint64 farmhash_uo_h(uint64 x, uint64 y, uint64 mul, int r)
		{
			uint64 a = (x ^ y) * mul;
			a ^= (a >> 47);
			uint64 b = (y ^ a) * mul;
			return ror64!(b, (uint)r) * mul;
		}
		
		private static uint64 farmhash64_uo_with_seeds(char8* str, int length, uint64 seed0, uint64 seed1)
		{
			char8* s = str;
			uint32 len = (uint32)length;

			if (len <= 64)
				return farmhash64_na_with_seeds(s, length, seed0, seed1);

			// For strings over 64 bytes we loop.  Internal state consists of 64 bytes: u, v, w, x, y, and z.
			uint64 x = seed0;
			uint64 y = seed1 * k2 + 113;
			uint64 z = smix(y * k2) * k2;
			uint128_c_t v = make_uint128_c_t!(seed0, seed1);
			uint128_c_t w = make_uint128_c_t!(0, 0);
			uint64 u = x - z;
			x *= k2;
			uint64 mul = k2 + (u & 0x82);
			
			// Set end so that after the loop we have 1 to 64 bytes left to process.
			char8* end = s + ((len - 1) / 64) * 64;
			char8* last64 = end + ((len - 1) & 63) - 63;
			//assert(s + len - 64 == last64);

			repeat {
				uint64 a0 = fetch64!(s);
				uint64 a1 = fetch64!(s + 8);
				uint64 a2 = fetch64!(s + 16);
				uint64 a3 = fetch64!(s + 24);
				uint64 a4 = fetch64!(s + 32);
				uint64 a5 = fetch64!(s + 40);
				uint64 a6 = fetch64!(s + 48);
				uint64 a7 = fetch64!(s + 56);
				x += a0 + a1;
				y += a2;
				z += a3;
				v.a += a4;
				v.b += a5 + a1;
				w.a += a6;
				w.b += a7;
				
				x = ror64!(x, 26);
				x *= 9;
				y = ror64!(y, 29);
				z *= mul;
				v.a = ror64!(v.a, 33);
				v.b = ror64!(v.b, 30);
				w.a ^= x;
				w.a *= 9;
				z = ror64!(z, 32);
				z += w.b;
				w.b += z;
				z *= 9;
				swap64!(&u, &y);
				
				z += a0 + a6;
				v.a += a2;
				v.b += a3;
				w.a += a4;
				w.b += a5 + a6;
				x += a1;
				y += a7;
				
				y += v.a;
				v.a += x - y;
				v.b += w.a;
				w.a += v.b;
				w.b += x - y;
				x += w.b;
				w.b = ror64!(w.b, 34);
				swap64!(&u, &z);
				s += 64;
			} while (s != end);

			// Make s point to the last 64 bytes of input.
			s = last64;
			u *= 9;
			v.b = ror64!(v.b, 28);
			v.a = ror64!(v.a, 20);
			w.a += ((len - 1) & 63);
			u += y;
			y += u;
			x = ror64!(y - x + v.a + fetch64!(s + 8), 37) * mul;
			y = ror64!(y ^ v.b ^ fetch64!(s + 48), 42) * mul;
			x ^= w.b * 9;
			y += v.a + fetch64!(s + 40);
			z = ror64!(z + w.a, 33) * mul;
			v = weak_farmhash_na_len_32_with_seeds!(s, v.b * mul, x + w.a);
			w = weak_farmhash_na_len_32_with_seeds!(s + 32, z + w.b, y + fetch64!(s + 16));
			return farmhash_uo_h(farmhash_len_16_mul!(v.a + x, w.a ^ y, mul) + z - u, farmhash_uo_h(v.b + y, w.b + z, k2, 30) ^ x, k2, 31);
		}

		[Inline]
		private static uint64 farmhash64_uo_with_seed(char8* s, int len, uint64 seed)
		{
			return len <= 64
				? farmhash64_na_with_seed(s, len, seed)
				: farmhash64_uo_with_seeds(s, len, 0, seed);
		}
		
		[Inline]
		private static uint64 farmhash64_uo(char8* s, int len)
		{
			return len <= 64
				? farmhash64_na(s, len)
				: farmhash64_uo_with_seeds(s, len, 81, 0);
		}

		// farmhash xo
		[Inline]
		private static uint64 farmhash_xo_h32(char8* s, int length, uint64 mul, uint64 seed0, uint64 seed1)
		{
			uint32 len = (uint32)length;
			uint64 a = fetch64!(s) * k1;
			uint64 b = fetch64!(s + 8);
			uint64 c = fetch64!(s + len - 8) * mul;
			uint64 d = fetch64!(s + len - 16) * k2;
			uint64 u = ror64!(a + b, 43) + ror64!(c, 30) + d + seed0;
			uint64 v = a + ror64!(b + k2, 18) + c + seed1;
			a = smix((u ^ v) * mul);
			return smix((v ^ a) * mul);
		}

		// Return an 8-byte hash for 33 to 64 bytes.
		[Inline]
		private static uint64 farmhash_xo_len_33_to_64(char8* s, int length)
		{
			uint32 len = (uint32)length;
			uint64 mul0 = k2 - 30;
			uint64 mul1 = k2 - 30 + 2 * len;
			uint64 h0 = farmhash_xo_h32(s, 32, mul0, 0, 0);
			uint64 h1 = farmhash_xo_h32(s + len - 32, 32, mul1, 0, 0);
			return ((h1 * mul1) + h0) * mul1;
		}

		// Return an 8-byte hash for 65 to 96 bytes.
		[Inline]
		private static uint64 farmhash_xo_len_65_to_96(char8* s, int length)
		{
			uint32 len = (uint32)length;
			uint64 mul0 = k2 - 114;
			uint64 mul1 = k2 - 114 + 2 * len;
			uint64 h0 = farmhash_xo_h32(s, 32, mul0, 0, 0);
			uint64 h1 = farmhash_xo_h32(s + 32, 32, mul1, 0, 0);
			uint64 h2 = farmhash_xo_h32(s + len - 32, 32, mul1, h0, h1);
			return (h2 * 9 + (h0 >> 17) + (h1 >> 21)) * mul1;
		}

		private static uint64 farmhash64_xo(char8* s, int len)
		{
			if (len <= 32) {
				return len <= 16
					? farmhash_na_len_0_to_16(s, len)
					: farmhash_na_len_17_to_32(s, len);
			} else if (len <= 64) {
				return farmhash_xo_len_33_to_64(s, len);
			} else if (len <= 96) {
				return farmhash_xo_len_65_to_96(s, len);
			} else if (len <= 256) {
				return farmhash64_na(s, len);
			} else {
				return farmhash64_uo(s, len);
			}
		}

		[Inline]
		private static uint64 farmhash64_xo_with_seeds(char8* s, int len, uint64 seed0, uint64 seed1)
		{
			return farmhash64_uo_with_seeds(s, len, seed0, seed1);
		}

		[Inline]
		private static uint64 farmhash64_xo_with_seed(char8* s, int len, uint64 seed)
		{
			return farmhash64_uo_with_seed(s, len, seed);
		}

		// farmhash te
#if BF_64_BIT && CAN_USE_SSE41 && CAN_USE_SSSE3
		/* Requires n >= 256.  Requires SSE4.1. Should be slightly faster if the
		** compiler uses AVX instructions (e.g., use the -mavx flag with GCC).
		*/
		[Inline]
		private static uint64 farmhash64_te_long(char8* str, uint n, uint64 seed0, uint64 seed1)
		{
			char8* s = str;

			__m128i k_shuf = _mm_set_epi8(4, 11, 10, 5, 8, 15, 6, 9, 12, 2, 14, 13, 0, 7, 3, 1);
			__m128i k_mult = _mm_set_epi8(0xBD, 0xD6, 0x33, 0x39, 0x45, 0x54, 0xFA, 0x03, 0x34, 0x3E, 0x33, 0xED, 0xCC, 0x9E, 0x2D, 0x51);
			uint64 seed2 = (seed0 + 113) * (seed1 + 9);
			uint64 seed3 = (ror64!(seed0, 23) + 27) * (ror64!(seed1, 30) + 111);
			__m128i d0 = _mm_cvtsi64_si128(seed0);
			__m128i d1 = _mm_cvtsi64_si128(seed1);
			__m128i d2 = shuf8x16!(k_shuf, d0);
			__m128i d3 = shuf8x16!(k_shuf, d1);
			__m128i d4 = xor128!(d0, d1);
			__m128i d5 = xor128!(d1, d2);
			__m128i d6 = xor128!(d2, d4);
			__m128i d7 = _mm_set1_epi32(seed2 >> 32);
			__m128i d8 = mul32x4!(k_mult, d2);
			__m128i d9 = _mm_set1_epi32(seed3 >> 32);
			__m128i d10 = _mm_set1_epi32(seed3);
			__m128i d11 = add64x2!(d2, _mm_set1_epi32(seed2));
			char8* end = s + (n & ~((uint) 255));

			repeat {
				__m128i z;
				z = fetch128!(s);
				d0 = add64x2!(d0, z);
				d1 = shuf8x16!(k_shuf, d1);
				d2 = xor128!(d2, d0);
				d4 = xor128!(d4, z);
				d4 = xor128!(d4, d1);
				swap128!(&d0, &d6);
				z = fetch128!(s + 16);
				d5 = add64x2!(d5, z);
				d6 = shuf8x16!(k_shuf, d6);
				d8 = shuf8x16!(k_shuf, d8);
				d7 = xor128!(d7, d5);
				d0 = xor128!(d0, z);
				d0 = xor128!(d0, d6);
				swap128!(&d5, &d11);
				z = fetch128!(s + 32);
				d1 = add64x2!(d1, z);
				d2 = shuf8x16!(k_shuf, d2);
				d4 = shuf8x16!(k_shuf, d4);
				d5 = xor128!(d5, z);
				d5 = xor128!(d5, d2);
				swap128!(&d10, &d4);
				z = fetch128!(s + 48);
				d6 = add64x2!(d6, z);
				d7 = shuf8x16!(k_shuf, d7);
				d0 = shuf8x16!(k_shuf, d0);
				d8 = xor128!(d8, d6);
				d1 = xor128!(d1, z);
				d1 = add64x2!(d1, d7);
				z = fetch128!(s + 64);
				d2 = add64x2!(d2, z);
				d5 = shuf8x16!(k_shuf, d5);
				d4 = add64x2!(d4, d2);
				d6 = xor128!(d6, z);
				d6 = xor128!(d6, d11);
				swap128!(&d8, &d2);
				z = fetch128!(s + 80);
				d7 = xor128!(d7, z);
				d8 = shuf8x16!(k_shuf, d8);
				d1 = shuf8x16!(k_shuf, d1);
				d0 = add64x2!(d0, d7);
				d2 = add64x2!(d2, z);
				d2 = add64x2!(d2, d8);
				swap128!(&d1, &d7);
				z = fetch128!(s + 96);
				d4 = shuf8x16!(k_shuf, d4);
				d6 = shuf8x16!(k_shuf, d6);
				d8 = mul32x4!(k_mult, d8);
				d5 = xor128!(d5, d11);
				d7 = xor128!(d7, z);
				d7 = add64x2!(d7, d4);
				swap128!(&d6, &d0);
				z = fetch128!(s + 112);
				d8 = add64x2!(d8, z);
				d0 = shuf8x16!(k_shuf, d0);
				d2 = shuf8x16!(k_shuf, d2);
				d1 = xor128!(d1, d8);
				d10 = xor128!(d10, z);
				d10 = xor128!(d10, d0);
				swap128!(&d11, &d5);
				z = fetch128!(s + 128);
				d4 = add64x2!(d4, z);
				d5 = shuf8x16!(k_shuf, d5);
				d7 = shuf8x16!(k_shuf, d7);
				d6 = add64x2!(d6, d4);
				d8 = xor128!(d8, z);
				d8 = xor128!(d8, d5);
				swap128!(&d4, &d10);
				z = fetch128!(s + 144);
				d0 = add64x2!(d0, z);
				d1 = shuf8x16!(k_shuf, d1);
				d2 = add64x2!(d2, d0);
				d4 = xor128!(d4, z);
				d4 = xor128!(d4, d1);
				z = fetch128!(s + 160);
				d5 = add64x2!(d5, z);
				d6 = shuf8x16!(k_shuf, d6);
				d8 = shuf8x16!(k_shuf, d8);
				d7 = xor128!(d7, d5);
				d0 = xor128!(d0, z);
				d0 = xor128!(d0, d6);
				swap128!(&d2, &d8);
				z = fetch128!(s + 176);
				d1 = add64x2!(d1, z);
				d2 = shuf8x16!(k_shuf, d2);
				d4 = shuf8x16!(k_shuf, d4);
				d5 = mul32x4!(k_mult, d5);
				d5 = xor128!(d5, z);
				d5 = xor128!(d5, d2);
				swap128!(&d7, &d1);
				z = fetch128!(s + 192);
				d6 = add64x2!(d6, z);
				d7 = shuf8x16!(k_shuf, d7);
				d0 = shuf8x16!(k_shuf, d0);
				d8 = add64x2!(d8, d6);
				d1 = xor128!(d1, z);
				d1 = xor128!(d1, d7);
				swap128!(&d0, &d6);
				z = fetch128!(s + 208);
				d2 = add64x2!(d2, z);
				d5 = shuf8x16!(k_shuf, d5);
				d4 = xor128!(d4, d2);
				d6 = xor128!(d6, z);
				d6 = xor128!(d6, d9);
				swap128!(&d5, &d11);
				z = fetch128!(s + 224);
				d7 = add64x2!(d7, z);
				d8 = shuf8x16!(k_shuf, d8);
				d1 = shuf8x16!(k_shuf, d1);
				d0 = xor128!(d0, d7);
				d2 = xor128!(d2, z);
				d2 = xor128!(d2, d8);
				swap128!(&d10, &d4);
				z = fetch128!(s + 240);
				d3 = add64x2!(d3, z);
				d4 = shuf8x16!(k_shuf, d4);
				d6 = shuf8x16!(k_shuf, d6);
				d7 = mul32x4!(k_mult, d7);
				d5 = add64x2!(d5, d3);
				d7 = xor128!(d7, z);
				d7 = xor128!(d7, d4);
				swap128!(&d3, &d9);
				s += 256;
			} while (s != end);

			d6 = add64x2!(mul32x4!(k_mult, d6), _mm_cvtsi64_si128(n));

			if (n % 256 != 0) {
				d7 = add64x2!(_mm_shuffle_epi32(d8, (0 << 6) + (3 << 4) + (2 << 2) + (1 << 0)), d7);
				d8 = add64x2!(mul32x4!(k_mult, d8), _mm_cvtsi64_si128(farmhash64_xo(s, n % 256)));
			}
			__m128i t[8];
			d0 = mul32x4!(k_mult, shuf8x16!(k_shuf, mul32x4!(k_mult, d0)));
			d3 = mul32x4!(k_mult, shuf8x16!(k_shuf, mul32x4!(k_mult, d3)));
			d9 = mul32x4!(k_mult, shuf8x16!(k_shuf, mul32x4!(k_mult, d9)));
			d1 = mul32x4!(k_mult, shuf8x16!(k_shuf, mul32x4!(k_mult, d1)));
			d0 = add64x2!(d11, d0);
			d3 = xor128!(d7, d3);
			d9 = add64x2!(d8, d9);
			d1 = add64x2!(d10, d1);
			d4 = add64x2!(d3, d4);
			d5 = add64x2!(d9, d5);
			d6 = xor128!(d1, d6);
			d2 = add64x2!(d0, d2);
			t[0] = d0;
			t[1] = d3;
			t[2] = d9;
			t[3] = d1;
			t[4] = d4;
			t[5] = d5;
			t[6] = d6;
			t[7] = d2;
			return farmhash64_xo((char8*)t, sizeof(__m128i));
		}

		[Inline]
		private static uint64 farmhash64_te(char8* s, int len)
		{
			// Empirically, farmhash xo seems faster until length 512.
			return len >= 512 ? farmhash64_te_long(s, len, k2, k1) : farmhash64_xo(s, len);
		}
		
		[Inline]
		private static uint64 farmhash64_te_with_seed(char8* s, int len, uint64 seed)
		{
			return len >= 512 ? farmhash64_te_long(s, len, k1, seed) : farmhash64_xo_with_seed(s, len, seed);
		}
		
		[Inline]
		private static uint64 farmhash64_te_with_seeds(char8* s, int len, uint64 seed0, uint64 seed1)
		{
			return len >= 512 ? farmhash64_te_long(s, len, seed0, seed1) : farmhash64_xo_with_seeds(s, len, seed0, seed1);
		}

#endif

		// farmhash nt
#if BF_64_BIT && CAN_USE_SSE41 && CAN_USE_SSSE3
		[Inline]
		private static uint32 farmhash32_nt(char8* s, int len) { return (uint32)farmhash64_te(s, len); }
		
		[Inline]
		private static uint32 farmhash32_nt_with_seed(char8* s, int len, uint32 seed) { return (uint32)farmhash64_te_with_seed(s, len, seed); }
#endif

		// farmhash mk
		[Inline]
		private static uint32 farmhash32_mk_len_13_to_24(char8* s, int length, uint32 seed)
		{
			uint32 len = (uint32)length;
			uint32 a = fetch32!(s - 4 + (len >> 1));
			uint32 b = fetch32!(s + 4);
			uint32 c = fetch32!(s + len - 8);
			uint32 d = fetch32!(s + (len >> 1));
			uint32 e = fetch32!(s);
			uint32 f = fetch32!(s + len - 4);
			uint32 h = d * c1 + len + seed;
			a = ror32!(a, 12) + f;
			h = mur(c, h) + a;
			a = ror32!(a, 3) + c;
			h = mur(e, h) + a;
			a = ror32!(a + f, 12) + d;
			h = mur(b ^ seed, h) + a;
			return fmix(h);
		}
		
		[Inline]
		private static uint32 farmhash32_mk_len_0_to_4(char8* s, int length, uint32 seed)
		{
			uint32 len = (uint32)length;
			uint32 b = seed;
			uint32 c = 9;
			uint i;

			for (i = 0; i < len; i++) {
				uint8 v = (uint8)s[i];
				b = b * c1 + v;
				c ^= b;
			}

			return fmix(mur(b, mur(len, c)));
		}
		
		[Inline]
		private static uint32 farmhash32_mk_len_5_to_12(char8* s, int len, uint32 seed)
		{
			uint32 a = (uint32)len, b = (uint32)len * 5, c = 9, d = b + seed;
			a += fetch32!(s);
			b += fetch32!(s + len - 4);
			c += fetch32!(s + ((len >> 1) & 4));
			return fmix(seed ^ mur(c, mur(b, mur(a, d))));
		}
		
		private static uint32 farmhash32_mk(char8* str, int length)
		{
			char8* s = str;
			uint32 len = (uint32)length;

			if (len <= 24) {
				return len <= 12
					? (len <= 4 ? farmhash32_mk_len_0_to_4(s, length, 0) : farmhash32_mk_len_5_to_12(s, length, 0))
					: farmhash32_mk_len_13_to_24(s, length, 0);
			}
		
			// len > 24
			uint32 h = len, g = c1 * len, f = g;
			uint32 a0 = ror32!(fetch32!(s + len - 4) * c1, 17) * c2;
			uint32 a1 = ror32!(fetch32!(s + len - 8) * c1, 17) * c2;
			uint32 a2 = ror32!(fetch32!(s + len - 16) * c1, 17) * c2;
			uint32 a3 = ror32!(fetch32!(s + len - 12) * c1, 17) * c2;
			uint32 a4 = ror32!(fetch32!(s + len - 20) * c1, 17) * c2;
			h ^= a0;
			h = ror32!(h, 19);
			h = h * 5 + 0xE6546B64;
			h ^= a2;
			h = ror32!(h, 19);
			h = h * 5 + 0xE6546B64;
			g ^= a1;
			g = ror32!(g, 19);
			g = g * 5 + 0xE6546B64;
			g ^= a3;
			g = ror32!(g, 19);
			g = g * 5 + 0xE6546B64;
			f += a4;
			f = ror32!(f, 19) + 113;
			uint iters = (len - 1) / 20;

			repeat {
				uint32 a = fetch32!(s);
				uint32 b = fetch32!(s + 4);
				uint32 c = fetch32!(s + 8);
				uint32 d = fetch32!(s + 12);
				uint32 e = fetch32!(s + 16);
				h += a;
				g += b;
				f += c;
				h = mur(d, h) + e;
				g = mur(c, g) + a;
				f = mur(b + e * c1, f) + d;
				f += g;
				g += f;
				s += 20;
			} while (--iters != 0);

			g = ror32!(g, 11) * c1;
			g = ror32!(g, 17) * c1;
			f = ror32!(f, 11) * c1;
			f = ror32!(f, 17) * c1;
			h = ror32!(h + g, 19);
			h = h * 5 + 0xE6546B64;
			h = ror32!(h, 17) * c1;
			h = ror32!(h + f, 19);
			h = h * 5 + 0xE6546B64;
			return ror32!(h, 17) * c1;
		}
		
		[Inline]
		private static uint32 farmhash32_mk_with_seed(char8* s, int len, uint32 seed)
		{
			if (len <= 24) {
				if (len >= 13)
					return farmhash32_mk_len_13_to_24(s, len, seed * c1);
				else if (len >= 5)
					return farmhash32_mk_len_5_to_12(s, len, seed);
				else
					return farmhash32_mk_len_0_to_4(s, len, seed);
			}

			uint32 h = farmhash32_mk_len_13_to_24(s, 24, seed ^ (uint32)len);
			return mur(farmhash32_mk(s + 24, len - 24) + seed, h);
		}

		// farmhash su
#if CAN_USE_AESNI && CAN_USE_SSE42
		private static uint32 farmhash32_su(char8* str, int length)
		{
			const uint32 seed = 81;
			char8* s = str;
			uint32 len = (uint32)length;

			if (len <= 24) {
				return len <= 12
					? (len <= 4 ? farmhash32_mk_len_0_to_4(s, len, 0) : farmhash32_mk_len_5_to_12(s, len, 0))
					: farmhash32_mk_len_13_to_24(s, len, 0);
			}

			if (len < 40) {
				uint32 a = (uint32)len, b = (uint32)((uint64)seed * c2), c = a + b;
				a += fetch32!(s + len - 4);
				b += fetch32!(s + len - 20);
				c += fetch32!(s + len - 16);
				uint32 d = a;
				a = ror32!(a, 21);
				a = mur(a, mur(b, _mm_crc32_u32(c, d)));
				a += fetch32!(s + len - 12);
				b += fetch32!(s + len - 8);
				d += a;
				a += d;
				b = mur(b, d) * c2;
				a = _mm_crc32_u32(a, b + c);
				return farmhash32_mk_len_13_to_24(s, (len + 1) / 2, a) + b;
			}

			__m128i cc1 = _mm_set1_epi32(c1);
			__m128i cc2 = _mm_set1_epi32(c2);
			__m128i h = _mm_set1_epi32(seed);
			__m128i g = _mm_set1_epi32((uint32)((uint64)c1 * seed));
			__m128i f = g;
			__m128i k = _mm_set1_epi32(0xe6546b64);
			__m128i q;
	
			if (len < 80) {
				__m128i a = fetch128!(s);
				__m128i b = fetch128!(s + 16);
				__m128i c = fetch128!(s + (len - 15) / 2);
				__m128i d = fetch128!(s + len - 32);
				__m128i e = fetch128!(s + len - 16);
				h = add32x4!(h, a);
				g = add32x4!(g, b);
				q = g;
				g = shuf32x4_0_3_2_1(g);
				f = add32x4!(f, c);
				__m128i be = add32x4!(b, mul32x4!(e, cc1));
				h = add32x4!(h, f);
				f = add32x4!(f, h);
				h = add32x4!(murk!(d, h, cc1, cc2, k), e);
				k = xor128!(k, _mm_shuffle_epi8(g, f));
				g = add32x4!(xor128!(c, g), a);
				f = add32x4!(xor128!(be, f), d);
				k = add32x4!(k, be);
				k = add32x4!(k, _mm_shuffle_epi8(f, h));
				f = add32x4v(f, g);
				g = add32x4!(g, f);
				g = add32x4!(_mm_set1_epi32(len), mul32x4!(g, cc1));
			} else {
				// len >= 80
				// The following is loosely modelled after farmhash32_mk.
				uint32 iters = (len - 1) / 80;
				len -= iters * 80;

				mixin CHUNK_AES() {
					__m128i a = fetch128!(s);
					__m128i b = fetch128!(s + 16);
					__m128i c = fetch128!(s + 32);
					__m128i d = fetch128!(s + 48);
					__m128i e = fetch128!(s + 64);
					h = add32x4!(h, a);
					g = add32x4!(g, b);
					g = shuf32x4_0_3_2_1(g);
					f = add32x4!(f, c);
					__m128i be = add32x4!(b, mul32x4!(e, cc1));
					h = add32x4!(h, f);
					f = add32x4!(f, h);
					h = add32x4!(h, d);
					q = add32x4!(q, e);
					h = rol32x4_17!(h);
					h = mul32x4!(h, cc1);
					k = xor128!(k, _mm_shuffle_epi8(g, f));
					g = add32x4!(xor128!(c, g), a);
					f = add32x4!(xor128!(be, f), d);
					swap128!(&f, &q);
					q = _mm_aesimc_si128(q);
					k = add32x4!(k, be);
					k = add32x4!(k, _mm_shuffle_epi8(f, h));
					f = add32x4!(f, g);
					g = add32x4!(g, f);
					f = mul32x4!(f, cc1);
				}

				q = g;
				while (iters-- != 0) {
					CHUNK_AES!();
					s += 80;
				}

				if (len != 0) {
					h = add32x4!(h, _mm_set1_epi32(len));
					s = s + len - 80;
					CHUNK_AES!();
				}
			}

			g = shuf32x4_0_3_2_1(g);
			k = xor128!(k, g);
			k = xor128!(k, q);
			h = xor128!(h, q);
			f = mul32x4!(f, cc1);
			k = mul32x4!(k, cc2);
			g = mul32x4!(g, cc1);
			h = mul32x4!(h, cc2);
			k = add32x4!(k, _mm_shuffle_epi8(g, f));
			h = add32x4!(h, f);
			f = add32x4!(f, h);
			g = add32x4!(g, k);
			k = add32x4!(k, g);
			k = xor128!(k, _mm_shuffle_epi8(f, h));
			__m128i buf[4];
			buf[0] = f;
			buf[1] = g;
			buf[2] = k;
			buf[3] = h;
			s = (char8*)buf;
			uint32 x = fetch32!(s);
			uint32 y = fetch32!(s + 4);
			uint32 z = fetch32!(s + 8);
			x = _mm_crc32_u32(x, fetch32!(s + 12));
			y = _mm_crc32_u32(y, fetch32!(s + 16));
			z = _mm_crc32_u32(z * c1, fetch32!(s + 20));
			x = _mm_crc32_u32(x, fetch32!(s + 24));
			y = _mm_crc32_u32(y * c1, fetch32!(s + 28));
			uint32 o = y;
			z = _mm_crc32_u32(z, fetch32!(s + 32));
			x = _mm_crc32_u32(x * c1, fetch32!(s + 36));
			y = _mm_crc32_u32(y, fetch32!(s + 40));
			z = _mm_crc32_u32(z * c1, fetch32!(s + 44));
			x = _mm_crc32_u32(x, fetch32!(s + 48));
			y = _mm_crc32_u32(y * c1, fetch32!(s + 52));
			z = _mm_crc32_u32(z, fetch32!(s + 56));
			x = _mm_crc32_u32(x, fetch32!(s + 60));
			return (o - x + y - z) * c1;
		}

		[Inline]
		public static uint32 farmhash32_su_with_seed(char8* s, int len, uint32 seed)
		{
			if (len <= 24) {
				return len >= 13
					? farmhash32_mk_len_13_to_24(s, len, seed * c1)
					: (len >= 5 ? farmhash32_mk_len_5_to_12(s, len, seed) : farmhash32_mk_len_0_to_4(s, len, seed));
			}

			uint32 h = farmhash32_mk_len_13_to_24(s, 24, seed ^ (uint32)len);
			return _mm_crc32_u32(farmhash32_su(s + 24, len - 24) + seed, h);
		}
#endif

		// farmhash sa
#if CAN_USE_SSE41 && CAN_USE_SSE42
		private static uint32 farmhash32_sa(char8* str, int length)
		{
			const uint32 seed = 81;
			char8* s = str;
			uint32 len = (uint32)length;

			if (len <= 24) {
				return len <= 12
					? (len <= 4 ? farmhash32_mk_len_0_to_4(s, len, 0) : farmhash32_mk_len_5_to_12(s, len, 0))
					: farmhash32_mk_len_13_to_24(s, len, 0);
			}

			if (len < 40) {
				uint32 a = len, b = (uint32)((uint64)seed * c2), c = a + b;
				a += fetch32!(s + len - 4);
				b += fetch32!(s + len - 20);
				c += fetch32!(s + len - 16);
				uint32 d = a;
				a = ror32!(a, 21);
				a = mur(a, mur(b, mur(c, d)));
				a += fetch32!(s + len - 12);
				b += fetch32!(s + len - 8);
				d += a;
				a += d;
				b = mur(b, d) * c2;
				a = _mm_crc32_u32(a, b + c);
				return farmhash32_mk_len_13_to_24(s, (len + 1) / 2, a) + b;
			}
	
			__m128i cc1 = _mm_set1_epi32(c1);
			__m128i cc2 = _mm_set1_epi32(c2);
			__m128i h = _mm_set1_epi32(seed);
			__m128i g = _mm_set1_epi32((uint32)((uint64)c1 * seed));
			__m128i f = g;
			__m128i k = _mm_set1_epi32(0xE6546B64);

			if (len < 80) {
				__m128i a = fetch128!(s);
				__m128i b = fetch128!(s + 16);
				__m128i c = fetch128!(s + (len - 15) / 2);
				__m128i d = fetch128!(s + len - 32);
				__m128i e = fetch128!(s + len - 16);
				h = add32x4!(h, a);
				g = add32x4!(g, b);
				g = shuf32x4_0_3_2_1(g);
				f = add32x4!(f, c);
				__m128i be = add32x4!(b, mul32x4!(e, cc1));
				h = add32x4!(h, f);
				f = add32x4!(f, h);
				h = add32x4!(murk!(d, h, cc1, cc2, k), e);
				k = xor128!(k, _mm_shuffle_epi8(g, f));
				g = add32x4!(xor128!(c, g), a);
				f = add32x4!(xor128!(be, f), d);
				k = add32x4!(k, be);
				k = add32x4!(k, _mm_shuffle_epi8(f, h));
				f = add32x4!(f, g);
				g = add32x4!(g, f);
				g = add32x4!(_mm_set1_epi32(len), mul32x4!(g, cc1));
			} else {
				// len >= 80
				// The following is loosely modelled after farmhash32_mk.
				uint32 iters = (len - 1) / 80;
				len -= iters * 80;
		
				mixin CHUNK() {
					__m128i a = fetch128!(s);
					__m128i b = fetch128!(s + 16);
					__m128i c = fetch128!(s + 32);
					__m128i d = fetch128!(s + 48);
					__m128i e = fetch128!(s + 64);
					h = add32x4!(h, a);
					g = add32x4!(g, b);
					g = shuf32x4_0_3_2_1(g);
					f = add32x4!(f, c);
					__m128i be = add32x4!(b, mul32x4!(e, cc1));
					h = add32x4!(h, f);
					f = add32x4!(f, h);
					h = add32x4!(murk!(d, h, cc1, cc2, k), e);
					k = xor128!(k, _mm_shuffle_epi8(g, f));
					g = add32x4!(xor128!(c, g), a);
					f = add32x4!(xor128!(be, f), d);
					k = add32x4!(k, be);
					k = add32x4!(k, _mm_shuffle_epi8(f, h));
					f = add32x4!(f, g);
					g = add32x4!(g, f);
					f = mul32x4!(f, cc1);
				}
		
				while (iters-- != 0) {
					CHUNK!();
					s += 80;
				}
		
				if (len != 0) {
					h = add32x4!(h, _mm_set1_epi32(len));
					s = s + len - 80;
					CHUNK!();
				}
			}
	
			g = shuf32x4_0_3_2_1(g);
			k = xor128!(k, g);
			f = mul32x4!(f, cc1);
			k = mul32x4!(k, cc2);
			g = mul32x4!(g, cc1);
			h = mul32x4!(h, cc2);
			k = add32x4!(k, _mm_shuffle_epi8(g, f));
			h = add32x4!(h, f);
			f = add32x4!(f, h);
			g = add32x4!(g, k);
			k = add32x4!(k, g);
			k = xor128!(k, _mm_shuffle_epi8(f, h));
			__m128i buf[4];
			buf[0] = f;
			buf[1] = g;
			buf[2] = k;
			buf[3] = h;
			s = (char8*)buf;
			uint32 x = fetch32!(s);
			uint32 y = fetch32!(s + 4);
			uint32 z = fetch32!(s + 8);
			x = _mm_crc32_u32(x, fetch32!(s + 12));
			y = _mm_crc32_u32(y, fetch32!(s + 16));
			z = _mm_crc32_u32(z * c1, fetch32!(s + 20));
			x = _mm_crc32_u32(x, fetch32!(s + 24));
			y = _mm_crc32_u32(y * c1, fetch32!(s + 28));
			uint32 o = y;
			z = _mm_crc32_u32(z, fetch32!(s + 32));
			x = _mm_crc32_u32(x * c1, fetch32!(s + 36));
			y = _mm_crc32_u32(y, fetch32!(s + 40));
			z = _mm_crc32_u32(z * c1, fetch32!(s + 44));
			x = _mm_crc32_u32(x, fetch32!(s + 48));
			y = _mm_crc32_u32(y * c1, fetch32!(s + 52));
			z = _mm_crc32_u32(z, fetch32!(s + 56));
			x = _mm_crc32_u32(x, fetch32!(s + 60));
			return (o - x + y - z) * c1;
		}

		[Inline]
		private static uint32 farmhash32_sa_with_seed(char8* s, int len, uint32 seed)
		{
			if (len <= 24) {
				return len >= 13
					? farmhash32_mk_len_13_to_24(s, len, seed * c1);
					: (len >= 5 ? farmhash32_mk_len_5_to_12(s, len, seed) : farmhash32_mk_len_0_to_4(s, len, seed));
			}

			uint32 h = farmhash32_mk_len_13_to_24(s, 24, seed ^ (uint32)len);
			return _mm_crc32_u32(farmhash32_sa(s + 24, len - 24) + seed, h);
		}
#endif

		// farmhash cc
		/* This file provides a 32-bit hash equivalent to cityhash32 (v1.1.1)
		** and a 128-bit hash equivalent to cityhash128 (v1.1.1).  It also provides
		** a seeded 32-bit hash function similar to cityhash32.
		*/
		[Inline]
		private static uint32 farmhash32_cc_len_13_to_24(char8* s, int length)
		{
			uint32 len = (uint32)length;
			uint32 a = fetch32!(s - 4 + (len >> 1));
			uint32 b = fetch32!(s + 4);
			uint32 c = fetch32!(s + len - 8);
			uint32 d = fetch32!(s + (len >> 1));
			uint32 e = fetch32!(s);
			uint32 f = fetch32!(s + len - 4);
			uint32 h = len;
			return fmix(mur(f, mur(e, mur(d, mur(c, mur(b, mur(a, h)))))));
		}

		[Inline]
		private static uint32 farmhash32_cc_len_0_to_4(char8* s, int length)
		{
			uint32 len = (uint32)length;
			uint32 b = 0;
			uint32 c = 9;
			uint i;

			for (i = 0; i < len; i++) {
				char8 v = s[i];
				b = b * c1 + (uint8)v;
				c ^= b;
			}

			return fmix(mur(b, mur(len, c)));
		}

		[Inline]
		private static uint32 farmhash32_cc_len_5_to_12(char8* s, int length)
		{
			uint32 len = (uint32)length;
			uint32 a = len, b = len * 5, c = 9, d = b;
			a += fetch32!(s);
			b += fetch32!(s + len - 4);
			c += fetch32!(s + ((len >> 1) & 4));
			return fmix(mur(c, mur(b, mur(a, d))));
		}
		
		private static uint32 farmhash32_cc(char8* str, int length)
		{
			uint32 len = (uint32)length;
			char8* s = str;

			if (len <= 24) {
				return len <= 12
					? (len <= 4 ? farmhash32_cc_len_0_to_4(s, length) : farmhash32_cc_len_5_to_12(s, length))
					: farmhash32_cc_len_13_to_24(s, length);
			}
			
			// len > 24
			uint32 h = len, g = c1 * len, f = g;
			uint32 a0 = ror32!(fetch32!(s + len - 4) * c1, 17) * c2;
			uint32 a1 = ror32!(fetch32!(s + len - 8) * c1, 17) * c2;
			uint32 a2 = ror32!(fetch32!(s + len - 16) * c1, 17) * c2;
			uint32 a3 = ror32!(fetch32!(s + len - 12) * c1, 17) * c2;
			uint32 a4 = ror32!(fetch32!(s + len - 20) * c1, 17) * c2;
			h ^= a0;
			h = ror32!(h, 19);
			h = h * 5 + 0xE6546B64;
			h ^= a2;
			h = ror32!(h, 19);
			h = h * 5 + 0xE6546B64;
			g ^= a1;
			g = ror32!(g, 19);
			g = g * 5 + 0xE6546B64;
			g ^= a3;
			g = ror32!(g, 19);
			g = g * 5 + 0xE6546B64;
			f += a4;
			f = ror32!(f, 19);
			f = f * 5 + 0xE6546B64;
			uint iters = (len - 1) / 20;

			repeat {
				a0 = ror32!(fetch32!(s) * c1, 17) * c2;
				a1 = fetch32!(s + 4);
				a2 = ror32!(fetch32!(s + 8) * c1, 17) * c2;
				a3 = ror32!(fetch32!(s + 12) * c1, 17) * c2;
				a4 = fetch32!(s + 16);
				h ^= a0;
				h = ror32!(h, 18);
				h = h * 5 + 0xE6546B64;
				f += a1;
				f = ror32!(f, 19);
				f = f * c1;
				g += a2;
				g = ror32!(g, 18);
				g = g * 5 + 0xE6546B64;
				h ^= a3 + a1;
				h = ror32!(h, 19);
				h = h * 5 + 0xE6546B64;
				g ^= a4;
				g = bswap32(g) * 5;
				h += a4 * 5;
				h = bswap32(h);
				f += a0;
				PERMUTE3!(&f, &h, &g);
				s += 20;
			} while (--iters != 0);

			g = ror32!(g, 11) * c1;
			g = ror32!(g, 17) * c1;
			f = ror32!(f, 11) * c1;
			f = ror32!(f, 17) * c1;
			h = ror32!(h + g, 19);
			h = h * 5 + 0xE6546B64;
			h = ror32!(h, 17) * c1;
			h = ror32!(h + f, 19);
			h = h * 5 + 0xE6546B64;
			return ror32!(h, 17) * c1;
		}

		[Inline]
		private static uint32 farmhash32_cc_with_seed(char8* str, int len, uint32 seed)
		{
			char8* s = str;
		
			if (len <= 24) {
				return len >= 13
					? farmhash32_mk_len_13_to_24(s, len, seed * c1)
					: (len >= 5 ? farmhash32_mk_len_5_to_12(s, len, seed) : farmhash32_mk_len_0_to_4(s, len, seed));
			}
		
			uint32 h = farmhash32_mk_len_13_to_24(s, 24, seed ^ (uint32)len);
			return mur(farmhash32_cc(s + 24, len - 24) + seed, h);
		}
		
		[Inline]
		private static uint64 farmhash_cc_len_0_to_16(char8* s, int length)
		{
			uint32 len = (uint32)length;

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
				uint32 y = ((uint32) a) + (((uint32) b) << 8);
				uint32 z = len + (((uint32) c) << 2);
				return smix(y * k2 ^ z * k0) * k2;
			}

			return k2;
		}

		// Return a 16-byte hash for 48 bytes.  Quick and dirty.
		// Callers do best to use "random-looking" values for a and b.
		[Inline]
		private static uint128_c_t weak_farmhash_cc_len_32_with_seeds_vals(uint64 w, uint64 x, uint64 y, uint64 z, uint64 a, uint64 b)
		{
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
		[Inline]
		private static uint128_c_t weak_farmhash_cc_len_32_with_seeds(char8* s, uint64 a, uint64 b)
		{
			return weak_farmhash_cc_len_32_with_seeds_vals(fetch64!(s), fetch64!(s + 8), fetch64!(s + 16), fetch64!(s + 24), a, b);
		}

		// A subroutine for cityhash128().  Returns a decent 128-bit hash for strings
		// of any length representable in signed long.  Based on City and Murmur.
		[Inline]
		private static uint128_c_t farmhash_cc_city_murmur(char8* str, int length, uint128_c_t seed)
		{
			uint32 len = (uint32)length;
			char8* s = str;
			uint64 a = uint128_c_t_low64!(seed);
			uint64 b = uint128_c_t_high64!(seed);
			uint64 c = 0;
			uint64 d = 0;
			uint32 l = len - 16;

			if (l <= 0) {  // len <= 16
				a = smix(a * k1) * k1;
				c = b * k1 + farmhash_cc_len_0_to_16(s, length);
				d = smix(a + (len >= 8 ? fetch64!(s) : c));
			} else {  // len > 16
				c = farmhash_len_16!(fetch64!(s + len - 8) + k1, a);
				d = farmhash_len_16!(b + len, c + fetch64!(s + len - 16));
				a += d;

				repeat {
					a ^= smix(fetch64!(s) * k1) * k1;
					a *= k1;
					b ^= a;
					c ^= smix(fetch64!(s + 8) * k1) * k1;
					c *= k1;
					d ^= c;
					s += 16;
					l -= 16;
				} while (l > 0);
			}

			a = farmhash_len_16!(a, c);
			b = farmhash_len_16!(d, b);
			return make_uint128_c_t!(a ^ b, farmhash_len_16!(b, a));
		}
			
		private static uint128_c_t farmhash128_cc_city_with_seed(char8* str, int length, uint128_c_t seed)
		{
			uint32 len = (uint32)length;
			char8* s = str;

			if (len < 128)
				return farmhash_cc_city_murmur(s, length, seed);

			// We expect len >= 128 to be the common case.  Keep 56 bytes of state:
			// v, w, x, y, and z.
			uint128_c_t v, w;
			uint64 x = uint128_c_t_low64!(seed);
			uint64 y = uint128_c_t_high64!(seed);
			uint64 z = len * k1;
			uint tail_done;
			
			v.a = ror64!(y ^ k1, 49) * k1 + fetch64!(s);
			v.b = ror64!(v.a, 42) * k1 + fetch64!(s + 8);
			w.a = ror64!(y + z, 35) * k1 + x;
			w.b = ror64!(x + fetch64!(s + 88), 53) * k1;
			
			// This is the same inner loop as cityhash64(), manually unrolled.
			repeat {
				x = ror64!(x + y + v.a + fetch64!(s + 8), 37) * k1;
				y = ror64!(y + v.b + fetch64!(s + 48), 42) * k1;
				x ^= w.b;
				y += v.a + fetch64!(s + 40);
				z = ror64!(z + w.a, 33) * k1;
				v = weak_farmhash_cc_len_32_with_seeds(s, v.b * k1, x + w.a);
				w = weak_farmhash_cc_len_32_with_seeds(s + 32, z + w.b, y + fetch64!(s + 16));
				swap64!(&z, &x);
				s += 64;
				x = ror64!(x + y + v.a + fetch64!(s + 8), 37) * k1;
				y = ror64!(y + v.b + fetch64!(s + 48), 42) * k1;
				x ^= w.b;
				y += v.a + fetch64!(s + 40);
				z = ror64!(z + w.a, 33) * k1;
				v = weak_farmhash_cc_len_32_with_seeds(s, v.b * k1, x + w.a);
				w = weak_farmhash_cc_len_32_with_seeds(s + 32, z + w.b, y + fetch64!(s + 16));
				swap64!(&z, &x);
				s += 64;
				len -= 128;
			} while (len >= 128);

			x += ror64!(v.a + z, 49) * k0;
			y = y * k0 + ror64!(w.b, 37);
			z = z * k0 + ror64!(w.a, 27);
			w.a *= 9;
			v.a *= k0;

			// If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s.
			for (tail_done = 0; tail_done < len; ) {
				tail_done += 32;
				y = ror64!(x + y, 42) * k0 + v.b;
				w.a += fetch64!(s + len - tail_done + 16);
				x = x * k0 + w.a;
				z += w.b + fetch64!(s + len - tail_done);
				w.b += v.a;
				v = weak_farmhash_cc_len_32_with_seeds(s + len - tail_done, v.a + z, v.b);
				v.a *= k0;
			}

			// At this point our 56 bytes of state should contain more than
			// enough information for a strong 128-bit hash.  We use two
			// different 56-byte-to-8-byte hashes to get a 16-byte final result.
			x = farmhash_len_16!(x, v.a);
			y = farmhash_len_16!(y + z, w.a);
			return make_uint128_c_t!(farmhash_len_16!(x + v.b, w.b) + y, farmhash_len_16!(x + w.b, y + v.b));
		}

		// BASIC STRING HASHING
		
		// Hash function for a byte array.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		[Inline]
		public static uint Hash(char8* s, int len)
		{
#if BF_64_BIT
			return Hash64(s, len);
#else
			return Hash32(s, len);
#endif
		}
		
		// Hash function for a byte array.  Most useful in 32-bit binaries.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		// As this short 32-bit variant leads to different hash values with the x86_64
		// SSE4.1 variant, compared to a 32bit or gcc <4.4 result, it is not portable and
		// not recommended. Disabled in SMHasher
		[Inline]
		public static uint32 Hash32(char8* s, int len)
		{
			return debug_tweak32!(
#if CAN_USE_SSE41 && BF_64_BIT
				farmhash32_nt(s, len)
#elif CAN_USE_SSE42 && CAN_USE_AESNI
				farmhash32_su(s, len)
#elif CAN_USE_SSE41 && CAN_USE_SSE42
				farmhash32_sa(s, len)
#else
				farmhash32_mk(s, len)
#endif
			);
		}

		// Hash function for a byte array.  For convenience, a 32-bit seed is also
		// hashed into the result.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		// As this short 32-bit variant leads to different hash values with the x86_64
		// SSE4.1 variant, compared to a 32bit or gcc <4.4 result, it is not portable and
		// not recommended. Disabled in SMHasher
		[Inline]
		public static uint32 Hash32_with_seed(char8* s, int len, uint32 seed)
		{
			return debug_tweak32!(
#if CAN_USE_SSE41 && BF_64_BIT
				farmhash32_nt_with_seed(s, len, seed)
#elif CAN_USE_SSE42 && CAN_USE_AESNI
				farmhash32_su_with_seed(s, len, seed)
#elif CAN_USE_SSE41 && CAN_USE_SSE42
				farmhash32_sa_with_seed(s, len, seed)
#else
				farmhash32_mk_with_seed(s, len, seed)
#endif
			);
		}
		
		// Hash 128 input bits down to 64 bits of output.
		// Hash function for a byte array.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		[Inline]
		public static uint64 Hash64(char8* s, int len)
		{
			return debug_tweak64!(
#if CAN_USE_SSE41 && CAN_USE_SSE42 && BF_64_BIT
				farmhash64_te(s, len)
#else
				farmhash64_xo(s, len)
#endif
			);
		}
		
		// Hash function for a byte array.  For convenience, a 64-bit seed is also
		// hashed into the result.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		[Inline]
		public static uint64 Hash64_with_seed(char8* s, int len, uint64 seed)
		{
			return debug_tweak64!(farmhash64_na_with_seed(s, len, seed));
		}
		
		// Hash function for a byte array.  For convenience, two seeds are also
		// hashed into the result.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		[Inline]
		public static uint64 Hash64_with_seeds(char8* s, int len, uint64 seed0, uint64 seed1)
		{
			return debug_tweak64!(farmhash64_na_with_seeds(s, len, seed0, seed1));
		}
		
		// Hash function for a byte array.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		[Inline]
		public static uint128_c_t Hash128(char8* s, int len)
		{
			return debug_tweak128!(Hash_cc_fingerprint128(s, len));
		}
		// Hash function for a byte array.  For convenience, a 128-bit seed is also
		// hashed into the result.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		[Inline]
		public static uint128_c_t Hash128_with_seed(char8* s, int len, uint128_c_t seed)
		{
			return debug_tweak128!(farmhash128_cc_city_with_seed(s, len, seed));
		}
		
		// BASIC NON-STRING HASHING
		
		// This is intended to be a reasonably good hash function.
		// May change from time to time, may differ on different platforms, may differ
		// depending on NDEBUG.
		[Inline]
		public static mixin Hash128_to_64(uint128_c_t x)
		{
			// Murmur-inspired hashing.
			uint64 a = (uint128_c_t_low64!(x) ^ uint128_c_t_high64!(x)) * MHB_K_MUL;
			a ^= (a >> 47);
			uint64 b = (uint128_c_t_high64!(x) ^ a) * MHB_K_MUL;
			b ^= (b >> 47);
			b * MHB_K_MUL
		}
		
		// FINGERPRINTING (i.e., good, portable, forever-fixed hash functions)
		
		// Fingerprint function for a byte array.  Most useful in 32-bit binaries.
		[Inline]
		public static uint32 Hash_fingerprint32(char8* s, int len) { return farmhash32_mk(s, len); }
		
		// Fingerprint function for a byte array.
		[Inline]
		public static uint64 Hash_fingerprint64(char8* s, int len) { return farmhash64_na(s, len); }

		[Inline]
		public static uint128_c_t Hash128_cc_city(char8* s, int len) {
			return len >= 16
				? farmhash128_cc_city_with_seed(s + 16, len - 16, make_uint128_c_t!(fetch64!(s), fetch64!(s + 8) + k0))
				: farmhash128_cc_city_with_seed(s, len, make_uint128_c_t!(k0, k1));
		}
		
		[Inline]
		public static uint128_c_t Hash_cc_fingerprint128(char8* s, int len) { return Hash128_cc_city(s, len); }
		
		// Fingerprint function for a byte array.
		[Inline]
		public static uint128_c_t Hash_fingerprint128(char8* s, int len) { return Hash_cc_fingerprint128(s, len); }
		
		// This is intended to be a good fingerprinting primitive.
		// See below for more overloads.
		public static mixin Hash_fingerprint_uint128_c_t(uint128_c_t x)
		{
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
		public static mixin Hash_fingerprint_uint64(uint64 x)
		{
			// Murmur-inspired hashing.
			uint64 b = x * MHB_K_MUL;
			b ^= (b >> 44);
			b *= MHB_K_MUL;
			b ^= (b >> 41);
			b * MHB_K_MUL
		}
	}
}
