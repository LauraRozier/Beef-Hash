using System;

namespace beef_hash
{
	// https://github.com/rurban/smhasher/blob/master/Spooky.cpp
	class SpookyHash
	{
		private const bool ALLOW_UNALIGNED_READS = true;

	    // number of uint64's in internal state
	    private const int sc_numVars = 12;
	
	    // size of the internal state
	    private const int sc_blockSize = sc_numVars * 8;
	
	    // size of buffer of unhashed data, in bytes
	    private const int sc_bufSize = 2 * sc_blockSize;
	
	    /*
	    ** sc_const: a constant which:
	    **  * is not zero
	    **  * is odd
	    **  * is a not-very-regular mix of 1's and 0's
	    **  * does not need any other special mathematical properties
	    */
	    private const uint64 sc_const = 0xDEADBEEFDEADBEEFUL;
	
	    private uint64[2 * sc_numVars] m_data; // unhashed data, for partial messages
	    private uint64[sc_numVars] m_state;    // internal state of the hash
	    private int m_length;                  // total length of the input so far
	    private uint8 m_remainder;             // length of unhashed data stashed in m_data

	    /*
	    ** Short is used for messages under 192 bytes in length
	    ** Short has a low startup cost, the normal mode is good for long keys, the cost crossover is at about 192
		** bytes.  The two modes were held to the same quality bar.
	    */
		[Union]
		private struct Short_data {
		    public uint8* p8;
		    public uint32* p32;
		    public uint64* p64;
		    public int i;
		}

	    private static void Short(void* message, int length, uint64* hash1, uint64* hash2)
		{
			uint64* buf = scope:: .[sc_numVars]*;
			Short_data u = .();
			u.p8 = (uint8*)message;

			if (!ALLOW_UNALIGNED_READS && (u.i & 0x7) > 0) {
			    Internal.MemCpy(buf, message, length);
			    u.p64 = buf;
			}

			int remainder = length % 32;
			uint64 a = *hash1;
			uint64 b = *hash2;
			uint64 c = sc_const;
			uint64 d = sc_const;

			if (length > 15) {
			    uint64* end = u.p64 + (uint64)(length / 32) * 4;
			    
			    // handle all complete sets of 32 bytes
			    for (; u.p64 < end; u.p64 += 4) {
			        c += u.p64[0];
			        d += u.p64[1];
			        ShortMix(ref a, ref b, ref c, ref d);
			        a += u.p64[2];
			        b += u.p64[3];
			    }
			    
			    //Handle the case of 16+ remaining bytes.
			    if (remainder >= 16) {
			        c += u.p64[0];
			        d += u.p64[1];
			        ShortMix(ref a, ref b, ref c, ref d);
			        u.p64 += 2;
			        remainder -= 16;
			    }
			}

			// Handle the last 0..15 bytes, and its length
			d = ((uint64)length) << 56;

			switch(remainder)
			{
				case 15: d += ((uint64)u.p8[14]) << 48; fallthrough;
				case 14: d += ((uint64)u.p8[13]) << 40; fallthrough;
				case 13: d += ((uint64)u.p8[12]) << 32; fallthrough;
				case 12: d += u.p32[2]; c += u.p64[0];
				case 11: d += ((uint64)u.p8[10]) << 16; fallthrough;
				case 10: d += ((uint64)u.p8[9]) << 8; fallthrough;
				case  9: d += (uint64)u.p8[8]; fallthrough;
				case  8: c += u.p64[0];
				case  7: c += ((uint64)u.p8[6]) << 48; fallthrough;
				case  6: c += ((uint64)u.p8[5]) << 40; fallthrough;
				case  5: c += ((uint64)u.p8[4]) << 32; fallthrough;
				case  4: c += u.p32[0];
				case  3: c += ((uint64)u.p8[2]) << 16; fallthrough;
				case  2: c += ((uint64)u.p8[1]) << 8; fallthrough;
				case  1: c += (uint64)u.p8[0];
				case  0: c += sc_const; d += sc_const;
			}

			ShortEnd(ref a, ref b, ref c, ref d);
			*hash1 = a;
			*hash2 = b;
		}

	    /*
	    ** left rotate a 64-bit value by k bytes
	    */
	    private static mixin Rot64(uint64 x, int k) { (x << k) | (x >> (64 - k)) }
	
	    /*
	    ** This is used if the input is 96 bytes long or longer.
	    **
	    ** The internal state is fully overwritten every 96 bytes.
	    ** Every input bit appears to cause at least 128 bits of entropy
	    ** before 96 other bytes are combined, when run forward or backward
	    **   For every input bit,
	    **   Two inputs differing in just that input bit
	    **   Where "differ" means xor or subtraction
	    **   And the base value is random
	    **   When run forward or backwards one Mix
	    ** I tried 3 pairs of each; they all differed by at least 212 bits.
	    */
		[Inline]
	    public static void Mix(uint64* data, ref uint64 s0, ref uint64 s1, ref uint64 s2, ref uint64 s3,
			ref uint64 s4, ref uint64 s5, ref uint64 s6, ref uint64 s7, ref uint64 s8, ref uint64 s9, ref uint64 s10,
			ref uint64 s11
		) {
			s0  += data[0];  s2  ^= s10; s11 ^= s0;  s0  = Rot64!(s0, 11);  s11 += s1;
			s1  += data[1];  s3  ^= s11; s0  ^= s1;  s1  = Rot64!(s1, 32);  s0 += s2;
			s2  += data[2];  s4  ^= s0;  s1  ^= s2;  s2  = Rot64!(s2, 43);  s1 += s3;
			s3  += data[3];  s5  ^= s1;  s2  ^= s3;  s3  = Rot64!(s3, 31);  s2 += s4;
			s4  += data[4];  s6  ^= s2;  s3  ^= s4;  s4  = Rot64!(s4, 17);  s3 += s5;
			s5  += data[5];  s7  ^= s3;  s4  ^= s5;  s5  = Rot64!(s5, 28);  s4 += s6;
			s6  += data[6];  s8  ^= s4;  s5  ^= s6;  s6  = Rot64!(s6, 39);  s5 += s7;
			s7  += data[7];  s9  ^= s5;  s6  ^= s7;  s7  = Rot64!(s7, 57);  s6 += s8;
			s8  += data[8];  s10 ^= s6;  s7  ^= s8;  s8  = Rot64!(s8, 55);  s7 += s9;
			s9  += data[9];  s11 ^= s7;  s8  ^= s9;  s9  = Rot64!(s9, 54);  s8 += s10;
			s10 += data[10]; s0  ^= s8;  s9  ^= s10; s10 = Rot64!(s10, 22); s9 += s11;
			s11 += data[11]; s1  ^= s9;  s10 ^= s11; s11 = Rot64!(s11, 46); s10 += s0;
	    }
	
	    /*
	    ** Mix all 12 inputs together so that h0, h1 are a hash of them all.
	    **
	    ** For two inputs differing in just the input bits
	    ** Where "differ" means xor or subtraction
	    ** And the base value is random, or a counting value starting at that bit
	    ** The final result will have each bit of h0, h1 flip
	    ** For every input bit,
	    ** with probability 50 +- .3%
	    ** For every pair of input bits,
	    ** with probability 50 +- 3%
	    **
	    ** This does not rely on the last Mix() call having already mixed some.
	    ** Two iterations was almost good enough for a 64-bit result, but a
	    ** 128-bit result is reported, so End() does three iterations.
	    */
		[Inline]
	    public static void EndPartial(ref uint64 h0, ref uint64 h1, ref uint64 h2,  ref uint64 h3, ref uint64 h4,
			ref uint64 h5, ref uint64 h6,  ref uint64 h7, ref uint64 h8, ref uint64 h9, ref uint64 h10, ref uint64 h11
		) {
	        h11 += h1;  h2  ^= h11; h1  = Rot64!(h1, 44);
			h0  += h2;  h3  ^= h0;  h2  = Rot64!(h2, 15);
			h1  += h3;  h4  ^= h1;  h3  = Rot64!(h3, 34);
			h2  += h4;  h5  ^= h2;  h4  = Rot64!(h4, 21);
			h3  += h5;  h6  ^= h3;  h5  = Rot64!(h5, 38);
			h4  += h6;  h7  ^= h4;  h6  = Rot64!(h6, 33);
			h5  += h7;  h8  ^= h5;  h7  = Rot64!(h7, 10);
			h6  += h8;  h9  ^= h6;  h8  = Rot64!(h8, 13);
			h7  += h9;  h10 ^= h7;  h9  = Rot64!(h9, 38);
			h8  += h10; h11 ^= h8;  h10 = Rot64!(h10, 53);
			h9  += h11; h0  ^= h9;  h11 = Rot64!(h11, 42);
			h10 += h0;  h1  ^= h10; h0  = Rot64!(h0, 54);
	    }
	
		[Inline]
		public static void End(ref uint64 h0, ref uint64 h1, ref uint64 h2,  ref uint64 h3, ref uint64 h4,
			ref uint64 h5, ref uint64 h6,  ref uint64 h7, ref uint64 h8, ref uint64 h9, ref uint64 h10, ref uint64 h11
		) {
	        EndPartial(ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);
	        EndPartial(ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);
	        EndPartial(ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);
	    }
	
	    /*
	    ** The goal is for each bit of the input to expand into 128 bits of 
	    **   apparent entropy before it is fully overwritten.
	    ** n trials both set and cleared at least m bits of h0 h1 h2 h3
	    **   n: 2   m: 29
	    **   n: 3   m: 46
	    **   n: 4   m: 57
	    **   n: 5   m: 107
	    **   n: 6   m: 146
	    **   n: 7   m: 152
	    ** when run forwards or backwards
	    ** for all 1-bit and 2-bit diffs
	    ** with diffs defined by either xor or subtraction
	    ** with a base of all zeros plus a counter, or plus another bit, or random
	    */
		[Inline]
	    public static void ShortMix(ref uint64 h0, ref uint64 h1, ref uint64 h2, ref uint64 h3)
	    {
	        h2 = Rot64!(h2, 50); h2 += h3; h0 ^= h2;
	        h3 = Rot64!(h3, 52); h3 += h0; h1 ^= h3;
	        h0 = Rot64!(h0, 30); h0 += h1; h2 ^= h0;
	        h1 = Rot64!(h1, 41); h1 += h2; h3 ^= h1;
	        h2 = Rot64!(h2, 54); h2 += h3; h0 ^= h2;
	        h3 = Rot64!(h3, 48); h3 += h0; h1 ^= h3;
	        h0 = Rot64!(h0, 38); h0 += h1; h2 ^= h0;
	        h1 = Rot64!(h1, 37); h1 += h2; h3 ^= h1;
	        h2 = Rot64!(h2, 62); h2 += h3; h0 ^= h2;
	        h3 = Rot64!(h3, 34); h3 += h0; h1 ^= h3;
	        h0 = Rot64!(h0, 5);  h0 += h1; h2 ^= h0;
	        h1 = Rot64!(h1, 36); h1 += h2; h3 ^= h1;
	    }
	
	    /*
	    ** Mix all 4 inputs together so that h0, h1 are a hash of them all.
	    **
	    ** For two inputs differing in just the input bits
	    ** Where "differ" means xor or subtraction
	    ** And the base value is random, or a counting value starting at that bit
	    ** The final result will have each bit of h0, h1 flip
	    ** For every input bit,
	    ** with probability 50 +- .3% (it is probably better than that)
	    ** For every pair of input bits,
	    ** with probability 50 +- .75% (the worst case is approximately that)
	    */
		[Inline]
	    public static void ShortEnd(ref uint64 h0, ref uint64 h1, ref uint64 h2, ref uint64 h3)
	    {
	        h3 ^= h2; h2 = Rot64!(h2, 15); h3 += h2;
	        h0 ^= h3; h3 = Rot64!(h3, 52); h0 += h3;
	        h1 ^= h0; h0 = Rot64!(h0, 26); h1 += h0;
	        h2 ^= h1; h1 = Rot64!(h1, 51); h2 += h1;
	        h3 ^= h2; h2 = Rot64!(h2, 28); h3 += h2;
	        h0 ^= h3; h3 = Rot64!(h3, 9);  h0 += h3;
	        h1 ^= h0; h0 = Rot64!(h0, 47); h1 += h0;
	        h2 ^= h1; h1 = Rot64!(h1, 54); h2 += h1;
	        h3 ^= h2; h2 = Rot64!(h2, 32); h3 += h2;
	        h0 ^= h3; h3 = Rot64!(h3, 25); h0 += h3;
	        h1 ^= h0; h0 = Rot64!(h0, 63); h1 += h0;
	    }

		
		/*
		** SpookyHash: hash a single message in one call, produce 128-bit output
		**
		** message : message to hash
		** length : length of message in bytes
		** hash1 : in/out: in seed 1, out hash value 1
		** hash2 : in/out: in seed 2, out hash value 2
		*/
		[Union]
		private struct Hash128_data {
			public uint8* p8; 
			public uint64* p64; 
			public int i; 
		}

		public static void Hash128(void* message, int length, uint64* hash1, uint64* hash2)
		{
			if (length < sc_bufSize) {
			    Short(message, length, hash1, hash2);
			    return;
			}

			uint64 h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11;
			uint64* buf = scope:: .[sc_numVars]*;
			uint64* end;
			Hash128_data u = .();
			int remainder;

			h0 = h3 = h6 = h9  = *hash1;
			h1 = h4 = h7 = h10 = *hash2;
			h2 = h5 = h8 = h11 = sc_const;

			u.p8 = (uint8*)message;
			end = u.p64 + (length/sc_blockSize)*sc_numVars;

			// handle all whole sc_blockSize blocks of bytes
			if (ALLOW_UNALIGNED_READS || ((u.i & 0x7) == 0)) {
			    while (u.p64 < end) { 
			        Mix(u.p64, ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);
			    	u.p64 += sc_numVars;
			    }
			} else {
			    while (u.p64 < end) {
			        Internal.MemCpy(buf, u.p64, sc_blockSize);
			        Mix(buf, ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);
			    	u.p64 += sc_numVars;
			    }
			}

			// handle the last partial block of sc_blockSize bytes
			remainder = (length - ((uint8*)end - (uint8*)message));
			Internal.MemCpy(buf, end, remainder);
			Internal.MemSet(((uint8*)buf) + remainder, 0, sc_blockSize - remainder);
			((uint8*)buf)[sc_blockSize - 1] = (uint8)remainder;
			Mix(buf, ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);

			// do some final mixing 
			End(ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);
			*hash1 = h0;
			*hash2 = h1;
		}

		/*
		** Hash64: hash a single message in one call, return 64-bit output
		**
		** message : message to hash
		** length : length of message in bytes
		** seed : seed
		*/
		public static uint64 Hash64(void* message, int length, uint64 seed)
		{
			uint64 s = seed;
		    uint64 hash1 = seed;
		    Hash128(message, length, &hash1, &s);
		    return hash1;
		}

		/*
		** Hash32: hash a single message in one call, produce 32-bit output
		**
		** message : message to hash
		** length : length of message in bytes
		** seed : seed
		*/
		public static uint32 Hash32(void* message, int length, uint32 seed)
		{
		    uint64 hash1 = seed, hash2 = seed;
		    Hash128(message, length, &hash1, &hash2);
		    return (uint32)hash1;
		}

		/*
		** Init: initialize the context of a SpookyHash
		**
		** seed1 : any 64-bit value will do, including 0
		** seed2 : different seeds produce independent hashes
		*/
		public void Init(uint64 seed1, uint64 seed2)
		{
			m_length = 0;
			m_remainder = 0;
			m_state[0] = seed1;
			m_state[1] = seed2;
		}

		/*
		** Update: add a piece of a message to a SpookyHash state
		**
		** message : message fragment
		** length : length of message fragment in bytes
		*/
		public void Update(void* message, int length)
		{
			int len = length;
			uint64 h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11;
			int newLength = len + m_remainder;
			uint8  remainder;
			Hash128_data u = .();
			uint64* end;
			
			// Is this message fragment too short?  If it is, stuff it away.
			if (newLength < sc_bufSize) {
				Internal.MemCpy(&((uint8*)&m_data)[m_remainder], message, len);
				m_length = len + m_length;
				m_remainder = (uint8)newLength;
				return;
			}
			
			// init the variables
			if (m_length < sc_bufSize) {
				h0 = h3 = h6 = h9  = m_state[0];
				h1 = h4 = h7 = h10 = m_state[1];
				h2 = h5 = h8 = h11 = sc_const;
			} else {
				h0 = m_state[0];
				h1 = m_state[1];
				h2 = m_state[2];
				h3 = m_state[3];
				h4 = m_state[4];
				h5 = m_state[5];
				h6 = m_state[6];
				h7 = m_state[7];
				h8 = m_state[8];
				h9 = m_state[9];
				h10 = m_state[10];
				h11 = m_state[11];
			}

			m_length = len + m_length;
			
			// if we've got anything stuffed away, use it now
			if (m_remainder > 0) {
				uint8 prefix = (uint8)(sc_bufSize - m_remainder);
				Internal.MemCpy(&(((uint8*)&m_data)[m_remainder]), message, prefix);
				u.p64 = &m_data;
				Mix(u.p64, ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);
				Mix(&u.p64[sc_numVars], ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);
				u.p8 = ((uint8*)message) + prefix;
				len -= prefix;
			} else {
				u.p8 = (uint8*)message;
			}
			
			// handle all whole blocks of sc_blockSize bytes
			end = u.p64 + (len/sc_blockSize)*sc_numVars;
			remainder = (uint8)(len - ((uint8*)end - u.p8));

			if (ALLOW_UNALIGNED_READS || (u.i & 0x7) == 0) {
				while (u.p64 < end) { 
					Mix(u.p64, ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);
					u.p64 += sc_numVars;
				}
			} else {
				while (u.p64 < end) { 
					Internal.MemCpy(&m_data, u.p8, sc_blockSize);
					Mix(&m_data, ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);
					u.p64 += sc_numVars;
				}
			}
			
			// stuff away the last few bytes
			m_remainder = remainder;
			Internal.MemCpy(&m_data, end, remainder);
			
			// stuff away the variables
			m_state[0] = h0;
			m_state[1] = h1;
			m_state[2] = h2;
			m_state[3] = h3;
			m_state[4] = h4;
			m_state[5] = h5;
			m_state[6] = h6;
			m_state[7] = h7;
			m_state[8] = h8;
			m_state[9] = h9;
			m_state[10] = h10;
			m_state[11] = h11;
		}


		/*
		** Final: compute the hash for the current SpookyHash state
		**
		** This does not modify the state; you can keep updating it afterward
		**
		** The result is the same as if SpookyHash() had been called with
		** all the pieces concatenated into one message.
		**
		** hash1 : out only: first 64 bits of hash value.
		** hash2 : out only: second 64 bits of hash value.
		*/
		public void Final(uint64* hash1, uint64* hash2)
		{
			// init the variables
			if (m_length < sc_bufSize) {
			    Short(&m_data, m_length, hash1, hash2);
			    return;
			}

			uint64* data = (uint64*)&m_data;
			uint8 remainder = m_remainder;

			uint64 h0 = m_state[0];
			uint64 h1 = m_state[1];
			uint64 h2 = m_state[2];
			uint64 h3 = m_state[3];
			uint64 h4 = m_state[4];
			uint64 h5 = m_state[5];
			uint64 h6 = m_state[6];
			uint64 h7 = m_state[7];
			uint64 h8 = m_state[8];
			uint64 h9 = m_state[9];
			uint64 h10 = m_state[10];
			uint64 h11 = m_state[11];

			if (remainder >= sc_blockSize) {
			    // m_data can contain two blocks; handle any whole first block
			    Mix(data, ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);
				data += sc_numVars;
				remainder -= sc_blockSize;
			}

			// mix in the last partial block, and the length mod sc_blockSize
			Internal.MemSet(&((uint8*)data)[remainder], 0, (sc_blockSize - remainder));

			((uint8*)data)[sc_blockSize - 1] = remainder;
			Mix(data, ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);

			// do some final mixing
			End(ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7, ref h8, ref h9, ref h10, ref h11);

			*hash1 = h0;
			*hash2 = h1;
		}
	}
}
