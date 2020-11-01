using System;

namespace beef_hash
{
	abstract class BobJenkins
	{
		/*-------------------------------------------------------------------------------
		** Original by Bob Jenkins, May 2006, Public Domain.
		** These are functions for producing 32-bit hashes for hash table lookup.
		** hashlittle(), mix(), and final() are externally useful functions.  You can
		** use this free for any purpose.  It's in the public domain.  It has no
		** warranty.
		** Why is this so big?  I read 12 bytes at a time into 3 4-byte integers, then
		** mix those integers.  This is fast (you can do a lot more thorough mixing with
		** 12*3 instructions on 3 integers than you can with 3 instructions on 1 byte),
		** but shoehorning those bytes into integers efficiently is messy.
		**-------------------------------------------------------------------------------
		*/
		private static mixin Rot(uint32 x, uint32 k)
		{
			(x << k) | (x >> (32 - k))
		}

		/*-------------------------------------------------------------------------------
		** mix -- mix 3 32-bit values reversibly.
		** This is reversible, so any information in (a,b,c) before mix() is still in
		** (a,b,c) after mix().
		** If four pairs of (a,b,c) inputs are run through mix(), or through mix() in
		** reverse, there are at least 32 bits of the output that are sometimes the same
		** for one pair and different for another pair.
		** This was tested for:
		** * pairs that differed by one bit, by two bits, in any combination of top bits
		**   of (a,b,c), or in any combination of bottom bits of (a,b,c).
		** * "differ" is defined as +, -, ^, or ~^.  For + and -, I transformed the
		**   output delta to a Gray code (a^(a>>1)) so a string of 1's (as is commonly
		**   produced by subtraction) look like a single 1-bit difference.
		** * the base values were pseudorandom, all zero but one bit set, or all zero
		**   plus a counter that starts at zero.
		** Some k values for my "a-=c; a^=rot(c,k); c+=b;" arrangement that satisfy this
		** are
		**     4  6  8 16 19  4
		**     9 15  3 18 27 15
		**    14  9  3  7 17  3
		** Well, "9 15 3 18 27 15" didn't quite get 32 bits diffing for "differ" defined
		** as + with a one-bit base and a two-bit delta.  I used
		** http://burtleburtle.net/bob/hash/avalanche.html to choose the operations,
		** constants, and arrangements of the variables.
		** This does not achieve avalanche.  There are input bits of (a,b,c) that fail to
		** affect some output bits of (a,b,c), especially of a.  The most thoroughly
		** mixed value is c, but it doesn't really even achieve avalanche in c.
		** This allows some parallelism.  Read-after-writes are good at doubling the
		** number of bits affected, so the goal of mixing pulls in the opposite direction
		** as the goal of parallelism.  I did what I could.  Rotates seem to cost as much
		** as shifts on every machine I could lay my hands on, and rotates are much
		** kinder to the top and bottom bits, so I used rotates.
		**-------------------------------------------------------------------------------
		*/
		private static mixin Mix(ref uint32 a, ref uint32 b, ref uint32 c)
		{
			a -= c; a ^= Rot!(c,  4); c += b;
			b -= a; b ^= Rot!(a,  6); a += c;
			c -= b; c ^= Rot!(b,  8); b += a;
			a -= c; a ^= Rot!(c, 16); c += b;
			b -= a; b ^= Rot!(a, 19); a += c;
			c -= b; c ^= Rot!(b,  4); b += a;
		}

		/*-------------------------------------------------------------------------------
		** final -- final mixing of 3 32-bit values (a,b,c) into c Pairs of (a,b,c)
		** values differing in only a few bits will usually produce values of c that look
		** totally different.  This was tested for
		** * pairs that differed by one bit, by two bits, in any combination of top bits
		**   of (a,b,c), or in any combination of bottom bits of (a,b,c).
		** * "differ" is defined as +, -, ^, or ~^.  For + and -, I transformed the
		**   output delta to a Gray code (a^(a>>1)) so a string of 1's (as is commonly
		**   produced by subtraction) look like a single 1-bit difference.
		** * the base values were pseudorandom, all zero but one bit set, or all zero
		**   plus a counter that starts at zero.
		** These constants passed:
		**  14 11 25 16 4 14 24
		**  12 14 25 16 4 14 24
		** and these came close:
		**   4  8 15 26 3 22 24
		**  10  8 15 26 3 22 24
		**  11  8 15 26 3 22 24
		**-------------------------------------------------------------------------------
		*/
		private static mixin Final(ref uint32 a, ref uint32 b, ref uint32 c)
		{
			c ^= b; c -= Rot!(b, 14);
			a ^= c; a -= Rot!(c, 11);
			b ^= a; b -= Rot!(a, 25);
			c ^= b; c -= Rot!(b, 16);
			a ^= c; a -= Rot!(c,  4);
			b ^= a; b -= Rot!(a, 14);
			c ^= b; c -= Rot!(b, 24);
		}

		/*-------------------------------------------------------------------------------
		** hashlittle() -- hash a variable-length key into a 32-bit value
		**   key     : the key (the unaligned variable-length array of bytes)
		**   length  : the length of the key, counting by bytes
		**   initVal : can be any 4-byte value
		** Returns a 32-bit value.  Every bit of the key affects every bit of the return
		** value.  Two keys differing by one or two bits will have totally different hash
		** values.
		** The best hash table sizes are powers of 2.  There is no need to do mod a prime
		** (mod is sooo slow!).  If you need less than 32 bits, use a bitmask.  For
		** example, if you need only 10 bits, do
		**   h = (h & hashmask(10));
		** In which case, the hash table should have hashsize(10) elements.
		** If you are hashing n strings (uint8_t **)k, do it like this:
		**   for (i=0, h=0; i<n; ++i) h = hashlittle( k[i], len[i], h);
		** By Bob Jenkins, 2006.  bob_jenkins@burtleburtle.net.  You may use this code
		** any way you wish, private, educational, or commercial.  It's free. Use for
		** hash table lookup, or anything where one collision in 2^^32 is acceptable.  Do
		** NOT use for cryptographic purposes.
		**-------------------------------------------------------------------------------
		*/
		public static uint32 HashLittle(void* key, int length, uint32 initVal = 0)
		{
			uint32 a, b, c;
			uint32 len = (uint32)length;

			a = b = c = 0xDEADBEEFU + len + initVal;

			// 4-byte aligned data
			if (((*(uint32*)key) & 3) == 0) {
				uint32* k = (uint32*)key;

				while (len > 12) {
				  	a += k[0];
				  	b += k[1];
				  	c += k[2];
				  	Mix!(ref a, ref b, ref c);
				  	len -= 12;
				  	k += 3;
				}

				switch (len)
				{
				    case 12: c += k[2]; b += k[1]; a += k[0]; break;
				    case 11: c += k[2] & 0xFFFFFF; b += k[1]; a += k[0]; break;
				    case 10: c += k[2] & 0xFFFF; b += k[1]; a += k[0]; break;
				    case  9: c += k[2] & 0xFF; b += k[1]; a += k[0]; break;
				    case  8: b += k[1]; a += k[0]; break;
				    case  7: b += k[1] & 0xFFFFFF; a += k[0]; break;
				    case  6: b += k[1] & 0xFFFF; a += k[0]; break;
				    case  5: b += k[1] & 0xFF; a += k[0]; break;
				    case  4: a += k[0]; break;
				    case  3: a += k[0] & 0xFFFFFF; break;
				    case  2: a += k[0] & 0xFFFF; break;
				    case  1: a += k[0] & 0xFF; break;
				    case  0: return c;              /* zero length strings require no mixing */
				}
			} else {
				// Ignoring rare case of 2-byte aligned data. This handles all other cases.
				uint8* k = (uint8*)key;

				while (len > 12) {
					a += k[0] + ((uint32)k[1] << 8) + ((uint32)k[2] << 16) + ((uint32)k[3] << 24);
					b += k[4] + ((uint32)k[5] << 8) + ((uint32)k[6] << 16) + ((uint32)k[7] << 24);
					c += k[8] + ((uint32)k[9] << 8) + ((uint32)k[10] << 16) + ((uint32)k[11] << 24);
					Mix!(ref a, ref b, ref c);
					len -= 12;
					k += 12;
				}

				/*-------------------------------- last block: affect all 32 bits of (c) */
				switch(len)                      /* all the case statements fall through */
				{
					case 12: c += ((uint32)k[11]) << 24;
					case 11: c += ((uint32)k[10]) << 16;
					case 10: c += ((uint32)k[9]) << 8;
					case  9: c += k[8];
					case  8: b += ((uint32)k[7]) << 24;
					case  7: b += ((uint32)k[6]) << 16;
					case  6: b += ((uint32)k[5]) << 8;
					case  5: b += k[4];
					case  4: a += ((uint32)k[3]) << 24;
					case  3: a += ((uint32)k[2]) << 16;
					case  2: a += ((uint32)k[1]) << 8;
					case  1: a += k[0]; break;
					case  0: return c;
				}
			}

			Final!(ref a, ref b, ref c);
			return c;
		}

		public static mixin Hash(StringView val, uint32 initVal = 0) { HashLittle(val.Ptr, val.Length, initVal) }

		public static mixin Hash(int val, uint32 initVal = 0)
		{
			var tmp = val;
			HashLittle(&tmp, sizeof(int), initVal)
		}

		public static mixin Hash(uint val, uint32 initVal = 0)
		{
			var tmp = val;
			HashLittle(&tmp, sizeof(uint), initVal)
		}
	}
}
