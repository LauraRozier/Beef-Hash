using System;

namespace beef_hash
{
	// https://github.com/rurban/smhasher/blob/master/mir-hash.h
	/* This file is a part of MIR project.
	** Copyright (C) 2018, 2019 Vladimir Makarov <vmakarov.gcc@gmail.com>.
	**
    ** Simple high-quality multiplicative hash passing demerphq-smhsher,
	** faster than spooky, city, or xxhash for strings less 100 bytes.
	** Hash for the same key can be different on different architectures.
	** To get machine-independent hash, use mir_hash_strict which is about
	** 1.5 times slower than mir_hash.
	*/
	abstract class MirHash
	{
/*
#if defined(__x86_64__) || defined(__i386__) || defined(__PPC64__) || defined(__s390__) \
  || defined(__m32c__) || defined(cris) || defined(__CR16__) || defined(__vax__)        \
  || defined(__m68k__) || defined(__aarch64__) || defined(_M_AMD64) || defined(_M_IX86)
*/
	#define MIR_HASH_UNALIGNED_ACCESS
/*
#else
	#define MIR_HASH_UNALIGNED_ACCESS
#endif
*/

#if BF_LITTLE_ENDIAN
		private const bool IS_LITTLE_ENDIAN = true;
#else
		private const bool IS_LITTLE_ENDIAN = false;
#endif

		[Inline]
		public static uint64 mir_get_key_part(uint8* v, uint len, int relax_p) {
			uint i, start = 0;
			uint64 tail = 0;

			if (relax_p > 0 || IS_LITTLE_ENDIAN) {
#if MIR_HASH_UNALIGNED_ACCESS
				if (len == sizeof(uint64))
					return *(uint64*)v;

				if (len >= sizeof (uint32)) {
					tail = (uint64)(*(uint32*)v) << 32;
					start = 4;
				}
#endif
			}

			for (i = start; i < len; i++) {
				tail = (tail >> 8) | ((uint64) v[i] << 56);
			}

			return tail;
		}

		private const uint64 p1 = 0X65862b62bdf5ef4dUL;
		private const uint64 p2 = 0X288eea216831e6a7UL;

		[Inline]
		public static uint64 mir_mum(uint64 v, uint64 c, int relax_p) {
			uint64 v1 = v >> 32, v2 = (uint32) v, c1 = c >> 32, c2 = (uint32) c, rm = v2 * c1 + v1 * c2;
			return v1 * c1 + (rm >> 32) + v2 * c2 + (rm << 32);
		}

		[Inline]
		public static uint64 mir_round(uint64 state, uint64 v, int relax_p) {
			uint64 s = state;
			s ^= mir_mum (v, p1, relax_p);
			return s ^ mir_mum (s, p2, relax_p);
		}

		[Inline]
		public static uint64 mir_hash_1(void* key, uint length, uint64 seed, int relax_p) {
			uint len = length;
			uint8* v = (uint8*)key;
			uint64 r = seed + len;

			for (; len >= 16; len -= 16, v += 16) {
				r ^= mir_mum (mir_get_key_part(v, 8, relax_p), p1, relax_p);
				r ^= mir_mum (mir_get_key_part(v + 8, 8, relax_p), p2, relax_p);
				r ^= mir_mum (r, p1, relax_p);
			}

			if (len >= 8) {
				r ^= mir_mum (mir_get_key_part(v, 8, relax_p), p1, relax_p);
				len -= 8;
				v += 8;
			}

			if (len != 0)
				r ^= mir_mum (mir_get_key_part(v, len, relax_p), p2, relax_p);

			return mir_round (r, r, relax_p);
		}

		public static mixin mir_hash(void* key, uint len, uint64 seed) { mir_hash_1(key, len, seed, 1) }

		public static mixin mir_hash_strict(void* key, uint len, uint64 seed) { mir_hash_1(key, len, seed, 0) }

		public static mixin mir_hash_init(uint64 seed) { seed }

		public static mixin mir_hash_step(uint64 h, uint64 key) { mir_round(h, key, 1) }

		public static mixin mir_hash_finish(uint64 h) { mir_round(h, h, 1) }

		public static mixin mir_hash64(uint64 key, uint64 seed) { mir_hash_finish!(mir_hash_step!(mir_hash_init!(seed), key)) }
	}
}
