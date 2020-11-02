using System;
using System.Diagnostics;
using beef_hash;

namespace beef_hash_test
{
	class Program
	{
		private const String SAMPLE_TEXT = "Sample Text";
		private const String LOREM_IPSUM = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
		private static int ONETWOTHREE_S = 123;
		private static uint ONETWOTHREE_U = 123U;

		static int Main()
		{
			int64 t1 = ?, t2 = ?, t3 = ?, t4 = ?;
			uint32 resultSample = ?, resultLorem = ?;
			uint64 result64Sample = ?, result64Lorem = ?;
			uint resultPSSample = ?, resultPSLorem = ?;
			String resultStrSample = null, resultStrLorem = null;

			/* ALDER-32 */
			t1 = Stopwatch.GetTimestamp();
			resultSample = Adler32.Hash!(SAMPLE_TEXT);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Adler32.Hash!(LOREM_IPSUM);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"\r\nAdler-32 :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Adler32.Hash!(ONETWOTHREE_S);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Adler32.Hash!(ONETWOTHREE_U);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Adler-32 Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Adler32.HashReverse!(SAMPLE_TEXT);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Adler32.HashReverse!(LOREM_IPSUM);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Adler-32 reverse-order :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Adler32.HashReverse!(ONETWOTHREE_S);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Adler32.HashReverse!(ONETWOTHREE_U);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Adler-32 Integers reverse-order :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			/* BOB JENKINS */
			t1 = Stopwatch.GetTimestamp();
			resultSample = BobJenkins.Hash!(SAMPLE_TEXT);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = BobJenkins.Hash!(LOREM_IPSUM);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"\r\nBob Jenkins :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = BobJenkins.Hash!(ONETWOTHREE_S);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = BobJenkins.Hash!(ONETWOTHREE_U);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Bob Jenkins Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			/* Murmur1 */
			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur1.Hash!(SAMPLE_TEXT);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur1.Hash!(LOREM_IPSUM);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"\r\nMurmur1 :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur1.Hash!(ONETWOTHREE_S);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur1.Hash!(ONETWOTHREE_U);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur1 Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur1.HashAligned!(SAMPLE_TEXT);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur1.HashAligned!(LOREM_IPSUM);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur1 Aligned :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur1.HashAligned!(ONETWOTHREE_S);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur1.HashAligned!(ONETWOTHREE_U);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur1 Aligned Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			/* Murmur2 */
			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur2.Hash!(SAMPLE_TEXT);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur2.Hash!(LOREM_IPSUM);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"\r\nMurmur2 :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur2.Hash!(ONETWOTHREE_S);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur2.Hash!(ONETWOTHREE_U);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur2 Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur2.HashA!(SAMPLE_TEXT);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur2.HashA!(LOREM_IPSUM);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur2_A :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur2.HashA!(ONETWOTHREE_S);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur2.HashA!(ONETWOTHREE_U);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur2_A Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			result64Sample = Murmur2.Hash64A!(SAMPLE_TEXT);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			result64Lorem = Murmur2.Hash64A!(LOREM_IPSUM);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur2_64A :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				result64Sample, t2 - t1,
				result64Lorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			result64Sample = Murmur2.Hash64A!(ONETWOTHREE_S);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			result64Lorem = Murmur2.Hash64A!(ONETWOTHREE_U);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur2_64A Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				result64Sample, t2 - t1,
				result64Lorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			result64Sample = Murmur2.Hash64B!(SAMPLE_TEXT);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			result64Lorem = Murmur2.Hash64B!(LOREM_IPSUM);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur2_64B :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				result64Sample, t2 - t1,
				result64Lorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			result64Sample = Murmur2.Hash64B!(ONETWOTHREE_S);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			result64Lorem = Murmur2.Hash64B!(ONETWOTHREE_U);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur2_64B Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				result64Sample, t2 - t1,
				result64Lorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur2.HashAligned!(SAMPLE_TEXT);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur2.HashAligned!(LOREM_IPSUM);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur2 Aligned :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur2.HashAligned!(ONETWOTHREE_S);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur2.HashAligned!(ONETWOTHREE_U);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur2 Aligned Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur2.HashNeutral!(SAMPLE_TEXT);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur2.HashNeutral!(LOREM_IPSUM);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur2 Neutral :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur2.HashNeutral!(ONETWOTHREE_S);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur2.HashNeutral!(ONETWOTHREE_U);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur2 Neutral Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			/* Murmur3 */
			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur3.Hash_32!(SAMPLE_TEXT);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur3.Hash_32!(LOREM_IPSUM);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"\r\nMurmur3_32 :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = Murmur3.Hash_32!(ONETWOTHREE_S);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = Murmur3.Hash_32!(ONETWOTHREE_U);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur3_32 Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			Murmur3.Hash_128!(SAMPLE_TEXT, resultStrSample, 0);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			Murmur3.Hash_128!(LOREM_IPSUM, resultStrLorem, 0);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur3_<CPU>_128 :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultStrSample, t2 - t1,
				resultStrLorem, t4 - t3
			);

			resultStrSample.Clear();
			resultStrLorem.Clear();
			t1 = Stopwatch.GetTimestamp();
			Murmur3.Hash_128!(ONETWOTHREE_S, resultStrSample, 0);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			Murmur3.Hash_128!(ONETWOTHREE_U, resultStrLorem, 0);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Murmur3_<CPU>_128 Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultStrSample, t2 - t1,
				resultStrLorem, t4 - t3
			);

			/* FarmHash */
			t1 = Stopwatch.GetTimestamp();
			resultPSSample = FarmHash.Hash(SAMPLE_TEXT.CStr(), SAMPLE_TEXT.Length * sizeof(char8));
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultPSLorem = FarmHash.Hash(LOREM_IPSUM.CStr(), LOREM_IPSUM.Length * sizeof(char8));
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"\r\nFarmHash :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultPSSample, t2 - t1,
				resultPSLorem, t4 - t3
			);
			
			t1 = Stopwatch.GetTimestamp();
			resultPSSample = FarmHash.Hash((char8*)&ONETWOTHREE_S, sizeof(int));
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultPSLorem = FarmHash.Hash((char8*)&ONETWOTHREE_U, sizeof(uint));
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"FarmHash Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultPSSample, t2 - t1,
				resultPSLorem, t4 - t3
			);

			/* Mum */
			t1 = Stopwatch.GetTimestamp();
			result64Sample = Mum.Hash(SAMPLE_TEXT.CStr(), SAMPLE_TEXT.Length * sizeof(char8), 0);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			result64Lorem = Mum.Hash(LOREM_IPSUM.CStr(), LOREM_IPSUM.Length * sizeof(char8), 0);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"\r\nMum :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				result64Sample, t2 - t1,
				result64Lorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			result64Sample = Mum.Hash64((uint64)ONETWOTHREE_S, 0);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			result64Lorem = Mum.Hash64(ONETWOTHREE_U, 0);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"Mum Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				result64Sample, t2 - t1,
				result64Lorem, t4 - t3
			);

			/* PengyHash */
			t1 = Stopwatch.GetTimestamp();
			result64Sample = PengyHash.Hash(SAMPLE_TEXT.CStr(), SAMPLE_TEXT.Length * sizeof(char8), 0);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			result64Lorem = PengyHash.Hash(LOREM_IPSUM.CStr(), LOREM_IPSUM.Length * sizeof(char8), 0);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"\r\nPengyHash :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				result64Sample, t2 - t1,
				result64Lorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			result64Sample = PengyHash.Hash(&ONETWOTHREE_S, sizeof(int), 0);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			result64Lorem = PengyHash.Hash(&ONETWOTHREE_U, sizeof(uint), 0);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"PengyHash Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				result64Sample, t2 - t1,
				result64Lorem, t4 - t3
			);

			/* PengyHash */
			t1 = Stopwatch.GetTimestamp();
			resultSample = SpookyHash.Hash32(SAMPLE_TEXT.CStr(), SAMPLE_TEXT.Length * sizeof(char8), 0);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = SpookyHash.Hash32(LOREM_IPSUM.CStr(), LOREM_IPSUM.Length * sizeof(char8), 0);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"\r\nSpookyHash_32 :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			result64Sample = SpookyHash.Hash64(SAMPLE_TEXT.CStr(), SAMPLE_TEXT.Length * sizeof(char8), 0);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			result64Lorem = SpookyHash.Hash64(LOREM_IPSUM.CStr(), LOREM_IPSUM.Length * sizeof(char8), 0);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"SpookyHash_64 :\r\n  Sample > {} in {} µs\r\n  Lorem > {} in {} µs",
				result64Sample, t2 - t1,
				result64Lorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			resultSample = SpookyHash.Hash32(&ONETWOTHREE_S, sizeof(int), 0);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			resultLorem = SpookyHash.Hash32(&ONETWOTHREE_U, sizeof(uint), 0);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"SpookyHash_32 Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				resultSample, t2 - t1,
				resultLorem, t4 - t3
			);

			t1 = Stopwatch.GetTimestamp();
			result64Sample = SpookyHash.Hash64(&ONETWOTHREE_S, sizeof(int), 0);
			t2 = Stopwatch.GetTimestamp();
			t3 = Stopwatch.GetTimestamp();
			result64Lorem = SpookyHash.Hash64(&ONETWOTHREE_U, sizeof(uint), 0);
			t4 = Stopwatch.GetTimestamp();
			Console.WriteLine(
				"SpookyHash_64 Integers :\r\n  int > {} in {} µs\r\n  uint > {} in {} µs",
				result64Sample, t2 - t1,
				result64Lorem, t4 - t3
			);

			Console.WriteLine("\r\nPress [Enter] to Exit . . .");
			Console.Read();
			return 0;
		}
	}
}
