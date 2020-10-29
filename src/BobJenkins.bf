using System;

namespace beef_hash
{
	abstract class BobJenkins
	{
		private static mixin Rot(uint32 x, uint32 k)
		{
			(x << k) | (x >> (32 - k))
		}
		
		private static mixin Mix(ref uint32 a, ref uint32 b, ref uint32 c)
		{
			a -= c; a ^= Rot!(c,  4); c += b;
			b -= a; b ^= Rot!(a,  6); a += c;
			c -= b; c ^= Rot!(b,  8); b += a;
			a -= c; a ^= Rot!(c, 16); c += b;
			b -= a; b ^= Rot!(a, 19); a += c;
			c -= b; c ^= Rot!(b,  4); b += a;
		}
		
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
				    case 11: c += k[2] & 0xffffff; b += k[1]; a += k[0]; break;
				    case 10: c += k[2] & 0xffff; b += k[1]; a += k[0]; break;
				    case 9 : c += k[2] & 0xff; b += k[1]; a += k[0]; break;
				    case 8 : b += k[1]; a += k[0]; break;
				    case 7 : b += k[1] & 0xffffff; a += k[0]; break;
				    case 6 : b += k[1] & 0xffff; a += k[0]; break;
				    case 5 : b += k[1] & 0xff; a += k[0]; break;
				    case 4 : a += k[0]; break;
				    case 3 : a += k[0] & 0xffffff; break;
				    case 2 : a += k[0] & 0xffff; break;
				    case 1 : a += k[0] & 0xff; break;
				    case 0 : return c;              /* zero length strings require no mixing */
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
					case 9 : c += k[8];
					case 8 : b += ((uint32)k[7]) << 24;
					case 7 : b += ((uint32)k[6]) << 16;
					case 6 : b += ((uint32)k[5]) << 8;
					case 5 : b += k[4];
					case 4 : a += ((uint32)k[3]) << 24;
					case 3 : a += ((uint32)k[2]) << 16;
					case 2 : a += ((uint32)k[1]) << 8;
					case 1 : a += k[0]; break;
					case 0 : return c;
				}
			}

			Final!(ref a, ref b, ref c);
			return c;
		}

		public static mixin Hash(StringView val, uint32 initVal = 0)
		{
			HashLittle(val.Ptr, val.Length, initVal)
		}

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
