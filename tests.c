#include <stdio.h>
#include <string.h>
#include "SHA3api_ref.h"
#include "skein.h"

const u64b_t precomputed[] =
   {0xD593DA0741E72355, 0x15B5E511AC73E00C,
    0x5180E5AEBAF2C4F0, 0x03BD41D3FCBCAFAF,
    0x1CAEC6FD1983A898, 0x6E510B8BCDD0589F,
    0x77E2BDFDC6394ADA, 0xC11E1DB524DCB0A3,
    0xD6D14AF9C6329AB5, 0x6A9B0BFC6EB67E0D,
    0x9243C60DCCFF1332, 0x1A1F1DDE743F02D4,
    0x0996753C10ED0BB8, 0x6572DD22F2B4969A,
    0x61FD3062D00A579A, 0x1DE0536E8682E539};


void CMNUpdate(Skein1024_Ctxt_t *ctx, const u08b_t *msg, size_t msgByteCnt) {
	size_t n;

	/* process full blocks, if any */
	if (msgByteCnt + ctx->h.bCnt > SKEIN1024_BLOCK_BYTES) {
		if (ctx->h.bCnt) {                            /* finish up any buffered message data */
			n = SKEIN1024_BLOCK_BYTES - ctx->h.bCnt;  /* # bytes free in buffer b[] */
			if (n) {
				memcpy(&ctx->b[ctx->h.bCnt],msg,n);
				msgByteCnt  -= n;
				msg         += n;
				ctx->h.bCnt += n;
			}
			Skein1024_Process_Block(ctx,ctx->b,1,SKEIN1024_BLOCK_BYTES);
			ctx->h.bCnt = 0;
		}
				
		/* now process any remaining full blocks, directly from input message data */
		if (msgByteCnt > SKEIN1024_BLOCK_BYTES) {
			n = (msgByteCnt-1) / SKEIN1024_BLOCK_BYTES;   /* number of full blocks to process */
			Skein1024_Process_Block(ctx,msg,n,SKEIN1024_BLOCK_BYTES);
			msgByteCnt -= n * SKEIN1024_BLOCK_BYTES;
			msg        += n * SKEIN1024_BLOCK_BYTES;
		}
	}

	/* copy any remaining source message data bytes into b[] */
	if (msgByteCnt)	{
		memcpy(&ctx->b[ctx->h.bCnt],msg,msgByteCnt);
		ctx->h.bCnt += msgByteCnt;
	}
}
	 
void CMNFinal(Skein1024_Ctxt_t *ctx, u08b_t *hashVal) {
	size_t i,n,byteCnt;
	u64b_t X[SKEIN1024_STATE_WORDS];

	ctx->h.T[1] |= SKEIN_T1_FLAG_FINAL;                 /* tag as the final block */
	if (ctx->h.bCnt < SKEIN1024_BLOCK_BYTES) {            /* zero pad b[] if necessary */
		memset(&ctx->b[ctx->h.bCnt],0,SKEIN1024_BLOCK_BYTES - ctx->h.bCnt);
	}

	Skein1024_Process_Block(ctx,ctx->b,1,ctx->h.bCnt);  /* process the final block */

	/* now output the result */
	byteCnt = (ctx->h.hashBitLen + 7) >> 3;             /* total number of output bytes */

	/* run Threefish in "counter mode" to generate output */
	memset(ctx->b,0,sizeof(ctx->b));  /* zero out b[], so it can hold the counter */
	memcpy(X,ctx->X,sizeof(X));       /* keep a local copy of counter mode "key" */
	for (i=0;i*SKEIN1024_BLOCK_BYTES < byteCnt;i++)	{
		((u64b_t *)ctx->b)[0] = Skein_Swap64((u64b_t) i); /* build the counter block */
		Skein_Start_New_Type(ctx,OUT_FINAL);
		Skein1024_Process_Block(ctx,ctx->b,1,sizeof(u64b_t)); /* run "counter mode" */
		n = byteCnt - i*SKEIN1024_BLOCK_BYTES;   /* number of output bytes left to go */
		if (n >= SKEIN1024_BLOCK_BYTES) {
			n  = SKEIN1024_BLOCK_BYTES;
		}
		Skein_Put64_LSB_First(hashVal+i*SKEIN1024_BLOCK_BYTES,ctx->X,n);   /* "output" the ctr mode bytes */
		memcpy(ctx->X,X,sizeof(X));   /* restore the counter mode key for next time */
	}
}





void HashCompact1024(const BitSequence *data, size_t databitlen, BitSequence *hashval) {
	hashState state_struct;
	hashState *state = &state_struct;
	state->statebits = 1024;

	// INIT
	////////////////////////////////////////////
	Skein1024_Ctxt_t *ctx = &state->u.ctx1024;
	ctx->h.hashBitLen = 1024;         /* output hash bit count */
	memcpy(ctx->X, precomputed, sizeof(ctx->X));
	Skein_Start_New_Type(ctx,MSG);    /* T0=0, T1= MSG type */	

	// Update
	////////////////////////////////////////////
	if ((databitlen & 7) == 0) {
		/* data is 8 byte aligned! */
		CMNUpdate(&state->u.ctx1024,data,databitlen >> 3);
	} else {   
		/* handle partial final byte(s) */
		size_t bCnt = (databitlen >> 3) + 1;                  /* number of bytes to handle (nonzero here!) */
		u08b_t b,mask;

		mask = (u08b_t) (1u << (7 - (databitlen & 7)));       /* partial byte bit mask */
		b    = (u08b_t) ((data[bCnt-1] & (0-mask)) | mask);   /* apply bit padding on final byte */

		CMNUpdate(&state->u.ctx1024,data,bCnt-1);      /* process all but the final byte    */
		CMNUpdate(&state->u.ctx1024,&b  ,  1   );      /* process the (masked) partial byte */

		(state->u.h).T[1] |= SKEIN_T1_FLAG_BIT_PAD;    /* set tweak flag for the final call */
	}
	
	// Final
	////////////////////////////////////////////
	CMNFinal(&state->u.ctx1024,hashval);
}













int NumberOfSetBits(u64b_t c) {
	// 64-bit method
	static const u64b_t S[] = {1,2,4,8,16,32};
	static const u64b_t B[] = {0x5555555555555555,
	                           0x3333333333333333,
	                           0x0F0F0F0F0F0F0F0F,
	                           0x00FF00FF00FF00FF,
	                           0x0000FFFF0000FFFF,
	                           0x00000000FFFFFFFF};

	c = c - ((c >> 1) & B[0]);
	c = ((c >> S[1]) & B[1]) + (c & B[1]);
	c = ((c >> S[2]) + c) & B[2];
	c = ((c >> S[3]) + c) & B[3];
	c = ((c >> S[4]) + c) & B[4];
	c = ((c >> S[5]) + c) & B[5];
	return c;
}

/* Compute two hashes (1 using the SHA3 implementation, the other using the minified code above) */
int main() {
	char *test1 = "AOALXXMTHQJGGRGWFJKMKMTLFTpoaYYq";  // should be 387 diff
	char *test2 = "CEZWYWWKQMOCGPEUYACJPWBEJYDQkWRL"; // should be 425 diff
	u64b_t hashval1[16], hashval2[16];
	int diff1 = 0, diff2 = 0, i;

	u64b_t target[] = {0x8082a05f5fa94d5b,0xc818f444df7998fc,
					   0x7d75b724a42bf1f9,0x4f4c0daefbbd2be0,
					   0x04fec50cc81793df,0x97f26c46739042c6,
					   0xf6d2dd9959c2b806,0x877b97cc75440d54,
					   0x8f9bf123e07b75f4,0x88b7862872d73540,
					   0xf99ca716e96d8269,0x247d34d49cc74cc9,
					   0x73a590233eaa67b5,0x4066675e8aa473a3,
					   0xe7c5e19701c79cc7,0xb65818ca53fb02f9};

	HashCompact1024((u08b_t *) test1, strlen(test1)*8, (u08b_t *) hashval1);
	HashCompact1024((u08b_t *) test2, strlen(test2)*8, (u08b_t *) hashval2);

	for(i = 0; i < 16; i++) {
		diff1 += NumberOfSetBits(target[i] ^ hashval1[i]);
		diff2 += NumberOfSetBits(target[i] ^ hashval2[i]);
	}

	if (diff1 != 387 || diff2 != 425) {
		printf("Diffs should be 387 and 425.  It is actuay %d and %d\n", diff1, diff2);
	} else { 
		printf("Tests passed!\n");
	}

	return 0;
}