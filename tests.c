#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* 
 * An attempt to gut the Skein1024 algorithm down to its bones.  Simpler is
 * easier to understand (and easier to write parallel processing ports).
 * Assumes:
 *  - 1024 bit encryption only
 *  - little endian system
 *  - data length is byte aligned (no partial bytes)
 *
 * Based the C code submitted to NIST in the 3rd round on 10/26/2010 from: http://www.schneier.com/skein.html
 */

#define BLOCK_BYTES (128)
#define STATE_WORDS (16)
#define KW_TWK_BASE     (0)
#define KW_KEY_BASE     (3)
#define ks              (kw + KW_KEY_BASE)                
#define ts              (kw + KW_TWK_BASE)
#define PARITY 0x1BD11BDAA9FC1A22

typedef struct
{
	size_t   hashBitLen;           /* size of hash result, in bits */
	size_t   bCnt;                 /* current byte count in buffer b[] */
	uint64_t T[2];                 /* tweak words: T[0]=byte cnt, T[1]=flags */
} Skein_Header_t;

typedef struct                     /* 1024-bit Skein hash context structure */
{
	Skein_Header_t h;              /* common header context variables */
	uint64_t  X[STATE_WORDS];      /* chaining variables */
	uint8_t   b[BLOCK_BYTES];      /* partial block buffer (8-byte aligned) */
} Skein_Context_t;

enum    
{
	/* Skein1024 round rotation constants */
	R1024_0_0=24, R1024_0_1=13, R1024_0_2= 8, R1024_0_3=47, R1024_0_4= 8, R1024_0_5=17, R1024_0_6=22, R1024_0_7=37,
	R1024_1_0=38, R1024_1_1=19, R1024_1_2=10, R1024_1_3=55, R1024_1_4=49, R1024_1_5=18, R1024_1_6=23, R1024_1_7=52,
	R1024_2_0=33, R1024_2_1= 4, R1024_2_2=51, R1024_2_3=13, R1024_2_4=34, R1024_2_5=41, R1024_2_6=59, R1024_2_7=17,
	R1024_3_0= 5, R1024_3_1=20, R1024_3_2=48, R1024_3_3=41, R1024_3_4=47, R1024_3_5=28, R1024_3_6=16, R1024_3_7=25,
	R1024_4_0=41, R1024_4_1= 9, R1024_4_2=37, R1024_4_3=31, R1024_4_4=12, R1024_4_5=47, R1024_4_6=44, R1024_4_7=30,
	R1024_5_0=16, R1024_5_1=34, R1024_5_2=56, R1024_5_3=51, R1024_5_4= 4, R1024_5_5=53, R1024_5_6=42, R1024_5_7=41,
	R1024_6_0=31, R1024_6_1=44, R1024_6_2=47, R1024_6_3=46, R1024_6_4=19, R1024_6_5=42, R1024_6_6=44, R1024_6_7=25,
	R1024_7_0= 9, R1024_7_1=48, R1024_7_2=35, R1024_7_3=52, R1024_7_4=23, R1024_7_5=31, R1024_7_6=37, R1024_7_7=20
};

#define RotL_64(x,N)    (((x) << (N)) | ((x) >> (64-(N))))

#define Round1024(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,pA,pB,pC,pD,pE,pF,ROT,rNum) \
		X##p0 += X##p1; X##p1 = RotL_64(X##p1,ROT##_0); X##p1 ^= X##p0;   \
		X##p2 += X##p3; X##p3 = RotL_64(X##p3,ROT##_1); X##p3 ^= X##p2;   \
		X##p4 += X##p5; X##p5 = RotL_64(X##p5,ROT##_2); X##p5 ^= X##p4;   \
		X##p6 += X##p7; X##p7 = RotL_64(X##p7,ROT##_3); X##p7 ^= X##p6;   \
		X##p8 += X##p9; X##p9 = RotL_64(X##p9,ROT##_4); X##p9 ^= X##p8;   \
		X##pA += X##pB; X##pB = RotL_64(X##pB,ROT##_5); X##pB ^= X##pA;   \
		X##pC += X##pD; X##pD = RotL_64(X##pD,ROT##_6); X##pD ^= X##pC;   \
		X##pE += X##pF; X##pF = RotL_64(X##pF,ROT##_7); X##pF ^= X##pE;   \

#define R1024(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,pA,pB,pC,pD,pE,pF,ROT,rn) \
		Round1024(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,pA,pB,pC,pD,pE,pF,ROT,rn) \

#define I1024(R)                                                      \
		X00   += ks[r+(R)+ 0];    /* inject the key schedule value */     \
		X01   += ks[r+(R)+ 1];                                            \
		X02   += ks[r+(R)+ 2];                                            \
		X03   += ks[r+(R)+ 3];                                            \
		X04   += ks[r+(R)+ 4];                                            \
		X05   += ks[r+(R)+ 5];                                            \
		X06   += ks[r+(R)+ 6];                                            \
		X07   += ks[r+(R)+ 7];                                            \
		X08   += ks[r+(R)+ 8];                                            \
		X09   += ks[r+(R)+ 9];                                            \
		X10   += ks[r+(R)+10];                                            \
		X11   += ks[r+(R)+11];                                            \
		X12   += ks[r+(R)+12];                                            \
		X13   += ks[r+(R)+13] + ts[r+(R)+0];                              \
		X14   += ks[r+(R)+14] + ts[r+(R)+1];                              \
		X15   += ks[r+(R)+15] +    r+(R)   ;                              \
		ks[r  +       (R)+16] = ks[r+(R)-1];  /* rotate key schedule */   \
		ts[r  +       (R)+ 2] = ts[r+(R)-1];                              \

#define R1024_8_rounds(R)    /* do 8 full rounds */                               \
			R1024(00,01,02,03,04,05,06,07,08,09,10,11,12,13,14,15,R1024_0,8*(R) + 1); \
			R1024(00,09,02,13,06,11,04,15,10,07,12,03,14,05,08,01,R1024_1,8*(R) + 2); \
			R1024(00,07,02,05,04,03,06,01,12,15,14,13,08,11,10,09,R1024_2,8*(R) + 3); \
			R1024(00,15,02,11,06,13,04,09,14,01,08,05,10,03,12,07,R1024_3,8*(R) + 4); \
			I1024(2*(R));                                                             \
			R1024(00,01,02,03,04,05,06,07,08,09,10,11,12,13,14,15,R1024_4,8*(R) + 5); \
			R1024(00,09,02,13,06,11,04,15,10,07,12,03,14,05,08,01,R1024_5,8*(R) + 6); \
			R1024(00,07,02,05,04,03,06,01,12,15,14,13,08,11,10,09,R1024_6,8*(R) + 7); \
			R1024(00,15,02,11,06,13,04,09,14,01,08,05,10,03,12,07,R1024_7,8*(R) + 8); \
			I1024(2*(R)+1);



void Process_Block(Skein_Context_t *ctx,const uint8_t *blkPtr, size_t blkCnt, size_t byteCntAdd)
{
	size_t  r;
	uint64_t kw[STATE_WORDS+4+20];                  /* key schedule words : chaining vars + tweak + "rotation"*/

	uint64_t X00,X01,X02,X03,X04,X05,X06,X07,    /* local copy of vars, for speed */
	         X08,X09,X10,X11,X12,X13,X14,X15;
	uint64_t w [STATE_WORDS];                           /* local copy of input block */

	ts[0] = ctx->h.T[0];
	ts[1] = ctx->h.T[1];
	
	do  {
		/* this implementation only supports 2**64 input bytes (no carry out here) */
		ts[0] += byteCntAdd;                    /* update processed length */

		/* precompute the key schedule for this block */
		ks[ 0] = ctx->X[ 0];
		ks[ 1] = ctx->X[ 1];
		ks[ 2] = ctx->X[ 2];
		ks[ 3] = ctx->X[ 3];
		ks[ 4] = ctx->X[ 4];
		ks[ 5] = ctx->X[ 5];
		ks[ 6] = ctx->X[ 6];
		ks[ 7] = ctx->X[ 7];
		ks[ 8] = ctx->X[ 8];
		ks[ 9] = ctx->X[ 9];
		ks[10] = ctx->X[10];
		ks[11] = ctx->X[11];
		ks[12] = ctx->X[12];
		ks[13] = ctx->X[13];
		ks[14] = ctx->X[14];
		ks[15] = ctx->X[15];
		ks[16] = ks[ 0] ^ ks[ 1] ^ ks[ 2] ^ ks[ 3] ^
		         ks[ 4] ^ ks[ 5] ^ ks[ 6] ^ ks[ 7] ^
		         ks[ 8] ^ ks[ 9] ^ ks[10] ^ ks[11] ^
		         ks[12] ^ ks[13] ^ ks[14] ^ ks[15] ^ PARITY;

		ts[2]  = ts[0] ^ ts[1];

		memcpy(w, blkPtr, 8*STATE_WORDS);


		X00    = w[ 0] + ks[ 0];                /* do the first full key injection */
		X01    = w[ 1] + ks[ 1];
		X02    = w[ 2] + ks[ 2];
		X03    = w[ 3] + ks[ 3];
		X04    = w[ 4] + ks[ 4];
		X05    = w[ 5] + ks[ 5];
		X06    = w[ 6] + ks[ 6];
		X07    = w[ 7] + ks[ 7];
		X08    = w[ 8] + ks[ 8];
		X09    = w[ 9] + ks[ 9];
		X10    = w[10] + ks[10];
		X11    = w[11] + ks[11];
		X12    = w[12] + ks[12];
		X13    = w[13] + ks[13] + ts[0];
		X14    = w[14] + ks[14] + ts[1];
		X15    = w[15] + ks[15];

		for (r=1; r <= 20; r+=2) {
			R1024_8_rounds(0);
		}

		/* do the final "feedforward" xor, update context chaining vars */

		ctx->X[ 0] = X00 ^ w[ 0];
		ctx->X[ 1] = X01 ^ w[ 1];
		ctx->X[ 2] = X02 ^ w[ 2];
		ctx->X[ 3] = X03 ^ w[ 3];
		ctx->X[ 4] = X04 ^ w[ 4];
		ctx->X[ 5] = X05 ^ w[ 5];
		ctx->X[ 6] = X06 ^ w[ 6];
		ctx->X[ 7] = X07 ^ w[ 7];
		ctx->X[ 8] = X08 ^ w[ 8];
		ctx->X[ 9] = X09 ^ w[ 9];
		ctx->X[10] = X10 ^ w[10];
		ctx->X[11] = X11 ^ w[11];
		ctx->X[12] = X12 ^ w[12];
		ctx->X[13] = X13 ^ w[13];
		ctx->X[14] = X14 ^ w[14];
		ctx->X[15] = X15 ^ w[15];

		ts[1] &= ~(1ULL << 62); /* flag = ~(POS_FIRST) */
		blkPtr += BLOCK_BYTES;

	} while (--blkCnt);

	ctx->h.T[0] = ts[0];
	ctx->h.T[1] = ts[1];
}



/*
 * Example usage:
 * char *data = "hello world!";
 * uint8_t  hashbuffer[128]; // buffer is always 1024 bits
 * HashCompact1024(data, strlen(data), hashbuffer);
 *
 * The algorithm processes the message in blocks (chunks of 1024 bits).
 */
void HashCompact1024(const uint8_t *msg, size_t msgByteCnt, uint8_t *hashVal) 
{
	/* INITIALIZE */
	/**************************************************/
	static const uint64_t precomputed[] = /* Starting value of hash - 128 bytes */
	{
		0xD593DA0741E72355, 0x15B5E511AC73E00C,	0x5180E5AEBAF2C4F0, 0x03BD41D3FCBCAFAF,
		0x1CAEC6FD1983A898, 0x6E510B8BCDD0589F,	0x77E2BDFDC6394ADA, 0xC11E1DB524DCB0A3,
		0xD6D14AF9C6329AB5, 0x6A9B0BFC6EB67E0D,	0x9243C60DCCFF1332, 0x1A1F1DDE743F02D4,
		0x0996753C10ED0BB8, 0x6572DD22F2B4969A,	0x61FD3062D00A579A, 0x1DE0536E8682E539
	};

	size_t n;
	Skein_Context_t ctx1024;
	Skein_Context_t *ctx = &ctx1024;
	uint64_t X[STATE_WORDS];
	
	/* Setup context */
	(ctx)->h.hashBitLen = 1024;
	memcpy(ctx->X, precomputed, sizeof(ctx->X));
	(ctx)->h.bCnt = 0;
	(ctx)->h.T[0] = 0;                            /* T[0]=byte cnt, T[1]=flags */
	(ctx)->h.T[1] = (1ULL << 62) | (48ULL << 56); /* flags = POS_FIRST | TYPE_MSG */

	/* UPDATE */
	/**************************************************/
	if (msgByteCnt > BLOCK_BYTES) {               /* process all full blocks (1024 bits) excluding the last block, if any */
		n = (msgByteCnt-1) / BLOCK_BYTES;         /* number of full blocks to process */
		Process_Block(ctx, msg, n, BLOCK_BYTES);
		msgByteCnt -= n * BLOCK_BYTES;
		msg        += n * BLOCK_BYTES;
	}

	/* Copy the last block (full or partial) of the source message into b[] */
	memcpy(ctx->b, msg, msgByteCnt);
	(ctx)->h.bCnt = msgByteCnt;
	memset(&ctx->b[ctx->h.bCnt], 0, BLOCK_BYTES - msgByteCnt); /* zero pad b[] to the BLOCK_BYTE boundary */
	
	/* FINALIZE */
	/**************************************************/
	(ctx)->h.T[1] |= (1ULL << 63);     /* flags = POS_FINAL */
	Process_Block(ctx, ctx->b, 1, ctx->h.bCnt);  /* process the final block */

	/* now output the result */
	memset(ctx->b, 0, sizeof(ctx->b));  /* zero out b[], so it can hold the counter */
	memcpy(X, ctx->X, sizeof(X));       /* keep a local copy of counter mode "key" */
	
	(ctx)->h.bCnt = 0;
	(ctx)->h.T[0] = 0;
	(ctx)->h.T[1] = (1ULL << 62) | (63ULL << 56) | (1ULL << 63); /* flags = POS_FIRST | OUT | FINAL */

	Process_Block(ctx, ctx->b, 1, sizeof(uint64_t));

	memcpy(hashVal, ctx->X, BLOCK_BYTES); /* "output" the ctr mode bytes */
}


int NumberOfSetBits(uint64_t c) 
{
	// 64-bit method
	static const uint64_t S[] = {1,2,4,8,16,32};
	static const uint64_t B[] = 
	{
		0x5555555555555555,
		0x3333333333333333,
		0x0F0F0F0F0F0F0F0F,
		0x00FF00FF00FF00FF,
		0x0000FFFF0000FFFF,
		0x00000000FFFFFFFF
	};

	c = c - ((c >> 1) & B[0]);
	c = ((c >> S[1]) & B[1]) + (c & B[1]);
	c = ((c >> S[2]) + c) & B[2];
	c = ((c >> S[3]) + c) & B[3];
	c = ((c >> S[4]) + c) & B[4];
	c = ((c >> S[5]) + c) & B[5];
	return c;
}



int main()
{
	char *test1 = "AOALXXMTHQJGGRGWFJKMKMTLFTpoaYYq"; // should be 387 diff
	char *test2 = "aaaaaaaaaaaaaaaaaaaaaffhilyDTxVUW"; // should be 406 diff
	uint64_t hashval1[16], hashval2[16];
	int diff1 = 0, diff2 = 0, i;

	uint64_t target[] = 
	{
		0x8082a05f5fa94d5b,0xc818f444df7998fc,0x7d75b724a42bf1f9,0x4f4c0daefbbd2be0,
		0x04fec50cc81793df,0x97f26c46739042c6,0xf6d2dd9959c2b806,0x877b97cc75440d54,
		0x8f9bf123e07b75f4,0x88b7862872d73540,0xf99ca716e96d8269,0x247d34d49cc74cc9,
		0x73a590233eaa67b5,0x4066675e8aa473a3,0xe7c5e19701c79cc7,0xb65818ca53fb02f9
	};

	HashCompact1024((uint8_t *) test1, strlen(test1), (uint8_t *) hashval1);
	HashCompact1024((uint8_t *) test2, strlen(test2), (uint8_t *) hashval2);

	for(i = 0; i < 16; i++) {
		diff1 += NumberOfSetBits(target[i] ^ hashval1[i]);
		diff2 += NumberOfSetBits(target[i] ^ hashval2[i]);
	}

	if (diff1 != 387 || diff2 != 406) {
		printf("Tests Failed. Diffs should be 387 and 406.  They are actually %d and %d\n", diff1, diff2);
	} else { 
		printf("Tests passed!\n");
	}

	return 0;
}