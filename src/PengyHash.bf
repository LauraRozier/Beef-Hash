using System;

namespace beef_hash
{
	/* pengyhash v0.2 */
	// https://github.com/rurban/smhasher/blob/master/pengyhash.c
	abstract class PengyHash
	{
		public static uint64 Hash(void* str, int length, uint32 seed)
		{
			int len = length;
			char8* p = (char8*)str;
			uint64[4] b = .(0, 0, 0, 0);
			uint64[4] s = .(0, 0, 0, (uint)len);
			int i;

			for(; len >= 32; len -= 32, p = p + 32) {
				Internal.MemCpy(&b[0], p, 32);
				
				s[1] = (s[0] += s[1] + b[3]) + (s[1] << 14 | s[1] >> 50);
				s[3] = (s[2] += s[3] + b[2]) + (s[3] << 23 | s[3] >> 41);
				s[3] = (s[0] += s[3] + b[1]) ^ (s[3] << 16 | s[3] >> 48);
				s[1] = (s[2] += s[1] + b[0]) ^ (s[1] << 40 | s[1] >> 24);
			}

			Internal.MemCpy(&b[0], p, len);

			for(i = 0; i < 6; i++) {
				s[1] = (s[0] += s[1] + b[3]) + (s[1] << 14 | s[1] >> 50) + seed;
				s[3] = (s[2] += s[3] + b[2]) + (s[3] << 23 | s[3] >> 41);
				s[3] = (s[0] += s[3] + b[1]) ^ (s[3] << 16 | s[3] >> 48);
				s[1] = (s[2] += s[1] + b[0]) ^ (s[1] << 40 | s[1] >> 24);
			}

			return s[0] + s[1] + s[2] + s[3];
		}
	}
}
