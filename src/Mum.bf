using System;

namespace beef_hash
{
	/*
	   Copyright (c) 2016 Vladimir Makarov <vmakarov@gcc.gnu.org>
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

	/*
	   This file implements MUM (MUltiply and Mix) hashing.  We randomize
	   input data by 64x64-bit multiplication and mixing hi- and low-parts
	   of the multiplication result by using an addition and then mix it
	   into the current state.  We use prime numbers randomly generated
	   with the equal probability of their bit values for the
	   multiplication.  When all primes are used once, the state is
	   randomized and the same prime numbers are used again for data
	   randomization.
	   The MUM hashing passes all SMHasher tests.  Pseudo Random Number
	   Generator based on MUM also passes NIST Statistical Test Suite for
	   Random and Pseudorandom Number Generators for Cryptographic
	   Applications (version 2.2.1) with 1000 bitstreams each containing
	   1M bits.  MUM hashing is also faster Spooky64 and City64 on small
	   strings (at least upto 512-bit) on Haswell and Power7.  The MUM bulk
	   speed (speed on very long data) is bigger than Spooky and City on
	   Power7.  On Haswell the bulk speed is bigger than Spooky one and
	   close to City speed.
	*/
	// https://github.com/rurban/smhasher/blob/master/mum.h
	abstract class Mum
	{
		private static Random rand = new .() ~ delete _;

		/*
		** Here are different primes randomly generated with the equal
		** probability of their bit values.  They are used to randomize input
		** values.
		*/
		static uint64 _mum_hash_step_prime = 0x2E0BB864E9EA7DF5UL;
		static uint64 _mum_key_step_prime = 0xCDB32970830FCAA1UL;
		static uint64 _mum_block_start_prime = 0xC42B5E2E6480B23BUL;
		static uint64 _mum_unroll_prime = 0x7B51EC3D22F7096FUL;
		static uint64 _mum_tail_prime = 0xAF47D47C99B1461BUL;
		static uint64 _mum_finish_prime1 = 0xA9A7AE7CEFF79F3FUL;
		static uint64 _mum_finish_prime2 = 0xAF47D47C99B1461BUL;

		static uint64[16] _mum_primes = .(
			0x9EBDCAE10D981691, 0x32B9B9B97A27AC7D, 0x29B5584D83D35BBD, 0x4B04E0E61401255F,
			0x25E8F7B1F1C9D027, 0x80D4C8C000F3E881, 0xBD1255431904B9DD, 0x8A3BD4485EEE6D81,
			0x3BC721B2AAD05197, 0x71B1A19B907D6E33, 0x525E6C1084A8534B, 0x9E4C2CD340C1299F,
			0xDE3ADD92E94CAA37, 0x7E14EADB1F65311D, 0x3F5AA40F89812853, 0x33B15A3B587D15C9
		);

		// Multiply 64-bit V and P and return sum of high and low parts of the result.
		[Inline]
		public static uint64 _mum(uint64 v, uint64 p)
		{
			uint64 hi, lo;
			// Implementation of 64x64->128-bit multiplication by four 32x32->64 bit multiplication.
			uint64 hv = v >> 32, hp = p >> 32;
			uint64 lv = (uint32)v, lp = (uint32)p;
			uint64 rh =  hv * hp;
			uint64 rm_0 = hv * lp;
			uint64 rm_1 = hp * lv;
			uint64 rl =  lv * lp;
			uint64 t, carry = 0;

			// We could ignore a carry bit here if we did not care about the same hash for 32-bit and 64-bit targets.
			t = rl + (rm_0 << 32);
#if MUM_TARGET_INDEPENDENT_HASH
			carry = t < rl;
#endif
			lo = t + (rm_1 << 32);
#if MUM_TARGET_INDEPENDENT_HASH
			carry += lo < t;
#endif
			hi = rh + (rm_0 >> 32) + (rm_1 >> 32) + carry;
			/*
			** We could use XOR here too but, for some reasons, on Haswell and Power7 using an addition improves
			** hashing performance by 10% for small strings.
			*/
			return hi + lo;
		}

		[Inline]
		private static uint32 _mum_bswap32(uint32 x)
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
		private static uint64 _mum_bswap64(uint64 x)
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

		public static mixin _mum_le(uint64 v)
		{
#if BF_LITTLE_ENDIAN || !MUM_TARGET_INDEPENDENT_HASH
			v
#else
			_mum_bswap64(v)
#endif
		}

		public static mixin _mum_le32(uint32 v)
		{
#if BF_LITTLE_ENDIAN || !MUM_TARGET_INDEPENDENT_HASH
			v
#else
			_mum_bswap32(v)
#endif
		}

		/*
		** Macro defining how many times the most nested loop in _mum_hash_aligned will be unrolled by the compiler
		** (although it can make an own decision:).  Use only a constant here to help a compiler to unroll a major
		** loop.  The macro value affects the result hash for strings > 128 bit.  The unroll factor greatly affects the
		** hashing speed.  We prefer the speed.
		*/
#if !_MUM_UNROLL_FACTOR_POWER
	#if BF_PPC64 && !MUM_TARGET_INDEPENDENT_HASH
		const uint32 _MUM_UNROLL_FACTOR_POWER = 3;
	#elif BF_AARCH64 && !MUM_TARGET_INDEPENDENT_HASH
		const uint32 _MUM_UNROLL_FACTOR_POWER = 4;
	#else
		const uint32 _MUM_UNROLL_FACTOR_POWER = 2;
	#endif
#endif
		const uint32 _MUM_UNROLL_FACTOR = 1 << _MUM_UNROLL_FACTOR_POWER;

		[Inline]
		public static uint64 _mum_hash_aligned(uint64 start, void* key, int length)
		{
			uint64 result = start;
			char8* str = (char8*)key;
			int len = length;
			uint64 u64;
			int i;
			int n;

			result = _mum(result, _mum_block_start_prime);

			while (len > _MUM_UNROLL_FACTOR * sizeof(uint64)) {
				/*
				** This loop could be vectorized when we have vector insns for 64x64->128-bit multiplication.
				** AVX2 currently only have a vector insn for 4 32x32->64-bit multiplication.
				*/
				for (i = 0; i < _MUM_UNROLL_FACTOR; i++) {
					result ^= _mum(_mum_le!(((uint64*)str)[i]), _mum_primes[i]);
				}

				len -= _MUM_UNROLL_FACTOR * sizeof(uint64);
				str += _MUM_UNROLL_FACTOR * sizeof(uint64);
				/* We will use the same prime numbers on the next iterations --
				randomize the state.  */
				result = _mum(result, _mum_unroll_prime);
			}

			n = len / sizeof(uint64);

			for (i = 0; i < n; i++) {
				result ^= _mum(_mum_le!(((uint64*)str)[i]), _mum_primes[i]);
			}

			len -= n * sizeof(uint64);
			str += n * sizeof(uint64);

			switch(len)
			{
				case 7: {
					u64 = _mum_le32!(*(uint32*)str);
					u64 |= (uint64)str[4] << 32;
					u64 |= (uint64)str[5] << 40;
					u64 |= (uint64)str[6] << 48;
					return result ^ _mum(u64, _mum_tail_prime);
				}
				case 6: {
					u64 = _mum_le32!(*(uint32*)str);
					u64 |= (uint64)str[4] << 32;
					u64 |= (uint64)str[5] << 40;
					return result ^ _mum(u64, _mum_tail_prime);
				}
				case 5: {
					u64 = _mum_le32!(*(uint32*)str);
					u64 |= (uint64)str[4] << 32;
					return result ^ _mum(u64, _mum_tail_prime);
				}
				case 4: {
					u64 = _mum_le32!(*(uint32*)str);
					return result ^ _mum(u64, _mum_tail_prime);
				}
				case 3: {
					u64 = (uint8)str[0];
					u64 |= (uint64)str[1] << 8;
					u64 |= (uint64)str[2] << 16;
					return result ^ _mum(u64, _mum_tail_prime);
				}
				case 2: {
					u64 = (uint8)str[0];
					u64 |= (uint64)str[1] << 8;
					return result ^ _mum(u64, _mum_tail_prime);
				}
				case 1: {
					u64 = (uint8)str[0];
					return result ^ _mum(u64, _mum_tail_prime);
				}
			}

			return result;
		}
			
		/* Final randomization of H.  */
		[Inline]
		public static uint64 _mum_final(uint64 hash) {
			uint64 h = hash;
			h ^= _mum(h, _mum_finish_prime1);
			h ^= _mum(h, _mum_finish_prime2);
			return h;
		}

#if !_MUM_UNALIGNED_ACCESS
	#if BF_64_BIT || BF_i386 || BF_PPC64 || BF_S390 || BF_M32C || BF_CRIS || BF_CR16 || BF_VAX || BF_M68K || BF_AARCH64 || BF_M_AMD64 || BF_M_IX86
		private const bool _MUM_UNALIGNED_ACCESS = true;
	#else
		private const bool _MUM_UNALIGNED_ACCESS = false;
	#endif
#endif

		/*
		** When we need an aligned access to data being hashed we move part of the unaligned data to an aligned block
		** of given size and then process it, repeating processing the data by the block.
		*/
		private const uint32 _MUM_BLOCK_LEN = 1024;

		[Inline]
		public static uint64 Hash_default(void* key, int length, uint64 seed)
		{
			uint64 result;
			int len = length;
			char8* str = (char8*)key;
			int block_len;
			uint64* buf = scope:: uint64[_MUM_BLOCK_LEN]*;
			
			result = seed + (uint)len;

			if (_MUM_UNALIGNED_ACCESS || ((int)*str & 0x7) == 0) {
				result = _mum_hash_aligned(result, key, len);
			} else {
				while (len != 0) {
					block_len = len < _MUM_BLOCK_LEN ? len : _MUM_BLOCK_LEN;
					Internal.MemMove(buf, str, block_len);
					result = _mum_hash_aligned(result, buf, block_len);
					len -= block_len;
					str += block_len;
				}
			}

			return _mum_final(result);
		}

		[Inline]
		private static uint64 _mum_next_factor()
		{
			uint64 start = 0;
			
			for (var i = 0; i < 8; i++) {
				start = (start << 8) | (uint32)(rand.NextS32() % 256);
			}

			return start;
		}

		/* ++++++++++++++++++++++++++ Interface functions: +++++++++++++++++++  */

		// Set random multiplicators depending on SEED.
		[Inline]
		public static void Hash_randomize(uint64 seed) {
			rand = new .((int)seed); // srand(seed); // Close enough
			_mum_hash_step_prime = _mum_next_factor();
			_mum_key_step_prime = _mum_next_factor();
			_mum_finish_prime1 = _mum_next_factor();
			_mum_finish_prime2 = _mum_next_factor();
			_mum_block_start_prime = _mum_next_factor();
			_mum_unroll_prime = _mum_next_factor();
			_mum_tail_prime = _mum_next_factor();

			for (var i = 0; i < 16; i++) {
				_mum_primes[i] = _mum_next_factor();
			}
		}

		// Start hashing data with SEED.  Return the state.
		[Inline]
		public static uint64 Hash_init(uint64 seed) { return seed; }
		
		// Process data KEY with the state H and return the updated state.
		[Inline]
		public static uint64 Hash_step(uint64 h, uint64 key) {
			return _mum(h, _mum_hash_step_prime) ^ _mum(key, _mum_key_step_prime);
		}
		
		// Return the result of hashing using the current state H.
		[Inline]
		public static uint64 Hash_finish(uint64 h) { return _mum_final(h); }
		
		// Fast hashing of KEY with SEED.  The hash is always the same for the same key on any target.
		[Inline]
		public static uint64 Hash64(uint64 key, uint64 seed) {
			return Hash_finish(Hash_step(Hash_init(seed), key));
		}
		
		// Hash data KEY of length LEN and SEED.  The hash depends on the target endianness and the unroll factor.
		[Inline]
		public static uint64 Hash(void* key, int len, uint64 seed) {
			return Hash_default(key, len, seed);
		}
	}
}
