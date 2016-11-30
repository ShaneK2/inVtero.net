//
//       Title: Tiger Hash for C#
//      Author: mastamac of Software Union
// ---------------------------------------
// Description: A speed-optimized native C# implementation of the cryptographic 
//              TIGER hash algorithm of 1995. Based on and usable through
//              .net Framework's HashAlgorithm class.
//     License: Common Development and Distribution License (CDDL)
// ############################################################################


using System;
using HashAlgorithm=System.Security.Cryptography.HashAlgorithm;


namespace softwareunion
{

	abstract public class BlockHashAlgorithm : HashAlgorithm
	{

		private byte[] ba_PartialBlockBuffer;
		private int i_PartialBlockFill;
		
		protected int i_InputBlockSize;
		protected long l_TotalBytesProcessed;


		/// <summary>Initializes a new instance of the BlockHashAlgorithm class.</summary>
		/// <param name="blockSize">The size in bytes of an individual block.</param>
		protected BlockHashAlgorithm(int blockSize,int hashSize) : base()
		{
			this.i_InputBlockSize = blockSize;
			this.HashSizeValue = hashSize;
			ba_PartialBlockBuffer = new byte[BlockSize];
		}


		/// <summary>Initializes the algorithm.</summary>
		/// <remarks>If this function is overriden in a derived class, the new function should call back to
		/// this function or you could risk garbage being carried over from one calculation to the next.</remarks>
		public override void Initialize()
		{	//abstract: base.Initialize();
			l_TotalBytesProcessed = 0;
			i_PartialBlockFill = 0;
			if(ba_PartialBlockBuffer==null) ba_PartialBlockBuffer=new byte[BlockSize];
		}


		/// <summary>The size in bytes of an individual block.</summary>
		public int BlockSize
		{
			get { return i_InputBlockSize; }
		}

		/// <summary>The number of bytes currently in the buffer waiting to be processed.</summary>
		public int BufferFill
		{
			get { return i_PartialBlockFill; }
		}

		
		/// <summary>Performs the hash algorithm on the data provided.</summary>
		/// <param name="array">The array containing the data.</param>
		/// <param name="ibStart">The position in the array to begin reading from.</param>
		/// <param name="cbSize">How many bytes in the array to read.</param>
		protected override void HashCore(byte[] array,int ibStart,int cbSize)
		{
			int i;

			// Use what may already be in the buffer.
			if(BufferFill > 0)
			{
				if(cbSize+BufferFill < BlockSize)
				{
					// Still don't have enough for a full block, just store it.
					Array.Copy(array,ibStart,ba_PartialBlockBuffer,BufferFill,cbSize);
					i_PartialBlockFill += cbSize;
					return;
				}
				else
				{
					// Fill out the buffer to make a full block, and then process it.
					i = BlockSize - BufferFill;
					Array.Copy(array,ibStart,ba_PartialBlockBuffer,BufferFill,i);
					ProcessBlock(ba_PartialBlockBuffer,0,1); l_TotalBytesProcessed += BlockSize;
					i_PartialBlockFill = 0; ibStart += i; cbSize -= i;
				}
			}

			// For as long as we have full blocks, process them.
			if(cbSize>=BlockSize)
			{	ProcessBlock(array,ibStart,cbSize/BlockSize);
				l_TotalBytesProcessed+=cbSize-cbSize%BlockSize;
			}
			/*for(i=0; i < (cbSize-cbSize%BlockSize); i+=BlockSize)
			{	ProcessBlock(array,ibStart + i,1);
				count += BlockSize;
			}*/

			// If we still have some bytes left, store them for later.
			int bytesLeft = cbSize % BlockSize;
			if(bytesLeft != 0)
			{
				Array.Copy(array,((cbSize - bytesLeft) + ibStart),ba_PartialBlockBuffer,0,bytesLeft);
				i_PartialBlockFill = bytesLeft;
			}
		}


		/// <summary>Performs any final activities required by the hash algorithm.</summary>
		/// <returns>The final hash value.</returns>
		protected override byte[] HashFinal()
		{
			return ProcessFinalBlock(ba_PartialBlockBuffer,0,i_PartialBlockFill);
		}


		/// <summary>Process a block of data.</summary>
		/// <param name="inputBuffer">The block of data to process.</param>
		/// <param name="inputOffset">Where to start in the block.</param>
		protected abstract void ProcessBlock(byte[] inputBuffer,int inputOffset,int inputLength);


		/// <summary>Process the last block of data.</summary>
		/// <param name="inputBuffer">The block of data to process.</param>
		/// <param name="inputOffset">Where to start in the block.</param>
		/// <param name="inputCount">How many bytes need to be processed.</param>
		/// <returns>The results of the completed hash calculation.</returns>
		protected abstract byte[] ProcessFinalBlock(byte[] inputBuffer,int inputOffset,int inputCount);


		internal static class BitTools
		{
			public static UInt16 RotLeft(UInt16 v,int b)
			{
				UInt32 i=v; i<<=16; i|=v;
				b%=16; i>>=b;
				return (UInt16)i;
			}
			public static UInt32 RotLeft(UInt32 v,int b)
			{
				UInt64 i=v; i<<=32; i|=v;
				b%=32; i>>=(32-b);
				return (UInt32)i;
			}

			public static void TypeBlindCopy(byte[] sourceArray,int sourceIndex,
					UInt32[] destinationArray,int destinationIndex,int sourceLength)
			{
				if(sourceIndex+sourceLength>sourceArray.Length ||
						destinationIndex+(sourceLength+3)/4>destinationArray.Length ||
						sourceLength%4!=0)
					throw new ArgumentException("BitTools.TypeBlindCopy: index or length boundary mismatch.");

				int iCtr; for(iCtr=0;iCtr<sourceLength;iCtr+=4,sourceIndex+=4,++destinationIndex)
					destinationArray[destinationIndex]=BitConverter.ToUInt32(sourceArray,sourceIndex);
			}
			public static void TypeBlindCopy(UInt32[] sourceArray,int sourceIndex,
					byte[] destinationArray,int destinationIndex,int sourceLength)
			{
				if(sourceIndex+sourceLength>sourceArray.Length ||
						destinationIndex+sourceLength*4>destinationArray.Length)
					throw new ArgumentException("BitTools.TypeBlindCopy: index or length boundary mismatch.");

				int iCtr; for(iCtr=0;iCtr<sourceLength;++iCtr,++sourceIndex,destinationIndex+=4)
					Array.Copy(BitConverter.GetBytes(sourceArray[sourceIndex]),
							0,destinationArray,destinationIndex,4);
			}
			public static void TypeBlindCopy(byte[] sourceArray,int sourceIndex,
					UInt64[] destinationArray,int destinationIndex,int sourceLength)
			{
				if(sourceIndex+sourceLength>sourceArray.Length ||
						destinationIndex+(sourceLength+7)/8>destinationArray.Length ||
						sourceLength%8!=0)
					throw new ArgumentException("BitTools.TypeBlindCopy: index or length boundary mismatch.");

				int iCtr; for(iCtr=0;iCtr<sourceLength;iCtr+=8,sourceIndex+=8,++destinationIndex)
					destinationArray[destinationIndex]=BitConverter.ToUInt64(sourceArray,sourceIndex);
			}
			public static void TypeBlindCopy(UInt64[] sourceArray,int sourceIndex,
					byte[] destinationArray,int destinationIndex,int sourceLength)
			{
				if(sourceIndex+sourceLength>sourceArray.Length ||
						destinationIndex+sourceLength*8>destinationArray.Length)
					throw new ArgumentException("BitTools.TypeBlindCopy: index or length boundary mismatch.");

				int iCtr; for(iCtr=0;iCtr<sourceLength;++iCtr,++sourceIndex,destinationIndex+=8)
					Array.Copy(BitConverter.GetBytes(sourceArray[sourceIndex]),
							0,destinationArray,destinationIndex,8);
			}

		}

	}

	public partial class Tiger:BlockHashAlgorithm
	{
		// registers
		private ulong[] accu, x;

		public Tiger():base(64,192)
		{	Initialize();
		}

		public override void Initialize()
		{
			base.Initialize();

			accu=new ulong[] { 0x0123456789ABCDEFUL, 0xFEDCBA9876543210UL, 0xF096A5B4C3B2E187UL };

			if(x==null) x=new ulong[8];
			else Array.Resize(ref x,8);
			Array.Clear(x,0,8);
		}

		private void Round(ref ulong x,ref ulong y,uint zh,uint zl)
		{	
			x -=   t1[(int)(byte)zl] ^ t2[(int)(byte)(zl>>16)]
                 ^ t3[(int)(byte)zh] ^ t4[(int)(byte)(zh>>16)];
			y +=   t4[(int)(byte)(zl>>8)] ^ t3[(int)(byte)(zl>>24)]
                 ^ t2[(int)(byte)(zh>>8)] ^ t1[(int)(byte)(zh>>24)];
		}

		private void KeySchedule(ref ulong x0, ref ulong x1, ref ulong x2, ref ulong x3,
				ref ulong x4, ref ulong x5, ref ulong x6, ref ulong x7)
		{
			x0 -= x7 ^ 0xA5A5A5A5A5A5A5A5UL;
			x1 ^= x0;
			x2 += x1;
			x3 -= x2 ^ ((~x1) << 19);
			x4 ^= x3;
			x5 += x4;
			x6 -= x5 ^ ((ulong)(~x4) >> 23);
			x7 ^= x6;
			x0 += x7;
			x1 -= x0 ^ ((~x7) << 19);
			x2 ^= x1;
			x3 += x2;
			x4 -= x3 ^ ((ulong)(~x2) >> 23);
			x5 ^= x4;
			x6 += x5;
			x7 -= x6 ^ 0x0123456789ABCDEFUL;
		}

		protected override void ProcessBlock(byte[] inputBuffer,int inputOffset,int iBlkCount)
		{	ulong a=accu[0], b=accu[1], c=accu[2],
			      x0, x1, x2, x3, x4, x5, x6, x7;
			
			int i,iSpaceNeeded=iBlkCount*8;
			if(x.Length<iSpaceNeeded) Array.Resize(ref x,iSpaceNeeded);
			BitTools.TypeBlindCopy(inputBuffer,inputOffset,x,0,iBlkCount*i_InputBlockSize);
			
			for(i=-1;iBlkCount>0;--iBlkCount,inputOffset+=i_InputBlockSize)
			{	
				x0=x[++i]; x1=x[++i]; x2=x[++i]; x3=x[++i];
				x4=x[++i]; x5=x[++i]; x6=x[++i]; x7=x[++i];

				// rounds and schedule
				c^=x0; Round(ref a,ref b,(uint)(c>>32),(uint)c); b*=5;
				a^=x1; Round(ref b,ref c,(uint)(a>>32),(uint)a); c*=5;
				b^=x2; Round(ref c,ref a,(uint)(b>>32),(uint)b); a*=5;
				c^=x3; Round(ref a,ref b,(uint)(c>>32),(uint)c); b*=5;
				a^=x4; Round(ref b,ref c,(uint)(a>>32),(uint)a); c*=5;
				b^=x5; Round(ref c,ref a,(uint)(b>>32),(uint)b); a*=5;
				c^=x6; Round(ref a,ref b,(uint)(c>>32),(uint)c); b*=5;
				a^=x7; Round(ref b,ref c,(uint)(a>>32),(uint)a); c*=5;

				KeySchedule(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7);

				b^=x0; Round(ref c,ref a,(uint)(b>>32),(uint)b); a*=7;
				c^=x1; Round(ref a,ref b,(uint)(c>>32),(uint)c); b*=7;
				a^=x2; Round(ref b,ref c,(uint)(a>>32),(uint)a); c*=7;
				b^=x3; Round(ref c,ref a,(uint)(b>>32),(uint)b); a*=7;
				c^=x4; Round(ref a,ref b,(uint)(c>>32),(uint)c); b*=7;
				a^=x5; Round(ref b,ref c,(uint)(a>>32),(uint)a); c*=7;
				b^=x6; Round(ref c,ref a,(uint)(b>>32),(uint)b); a*=7;
				c^=x7; Round(ref a,ref b,(uint)(c>>32),(uint)c); b*=7;

				KeySchedule(ref x0,ref x1,ref x2,ref x3,ref x4,ref x5,ref x6,ref x7);

				a^=x0; Round(ref b,ref c,(uint)(a>>32),(uint)a); c*=9;
				b^=x1; Round(ref c,ref a,(uint)(b>>32),(uint)b); a*=9;
				c^=x2; Round(ref a,ref b,(uint)(c>>32),(uint)c); b*=9;
				a^=x3; Round(ref b,ref c,(uint)(a>>32),(uint)a); c*=9;
				b^=x4; Round(ref c,ref a,(uint)(b>>32),(uint)b); a*=9;
				c^=x5; Round(ref a,ref b,(uint)(c>>32),(uint)c); b*=9;
				a^=x6; Round(ref b,ref c,(uint)(a>>32),(uint)a); c*=9;
				b^=x7; Round(ref c,ref a,(uint)(b>>32),(uint)b); a*=9;

				// feed forward
				a=accu[0]^=a; b-=accu[1]; accu[1]=b; c=accu[2]+=c;
			}
		}

		protected override byte[] ProcessFinalBlock(byte[] inputBuffer,int inputOffset,int inputCount)
		{	int paddingSize;

			// Figure out how much padding is needed between the last byte and the size.
			paddingSize = (int)(((ulong)inputCount + (ulong)l_TotalBytesProcessed) % (ulong)BlockSize);
			paddingSize = (BlockSize - 8) - paddingSize;
			if(paddingSize < 1) { paddingSize += BlockSize; }

			// Create the final, padded block(s).
			if(inputOffset>0&&inputCount>0) Array.Copy(inputBuffer,inputOffset,inputBuffer,0,inputCount);
			inputOffset=0;

			Array.Clear(inputBuffer,inputCount,BlockSize-inputCount);
			inputBuffer[inputCount] = 0x01; //0x80;
			ulong msg_bit_length = ((ulong)l_TotalBytesProcessed + (ulong)inputCount)<<3;

			if(inputCount+8 >= BlockSize)
			{
				if(inputBuffer.Length < 2*BlockSize) Array.Resize(ref inputBuffer,2*BlockSize);
				ProcessBlock(inputBuffer,inputOffset,1);
				inputOffset+=BlockSize; inputCount-=BlockSize;
			}

			for(inputCount=inputOffset+BlockSize-sizeof(ulong);msg_bit_length!=0;
					inputBuffer[inputCount]=(byte)msg_bit_length,msg_bit_length>>=8,++inputCount) ;
			ProcessBlock(inputBuffer,inputOffset,1);


			HashValue=new byte[HashSizeValue/8];
			BitTools.TypeBlindCopy(accu,0,HashValue,0,3); return HashValue;
		}

	}

}
