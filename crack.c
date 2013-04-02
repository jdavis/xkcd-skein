#include <curl/curl.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "skein.h"
#include "SHA3api_ref.h"

u08b_t target[] = {0x5b,0x4d,0xa9,0x5f,0x5f,0xa0,0x82,0x80,
                   0xfc,0x98,0x79,0xdf,0x44,0xf4,0x18,0xc8,
                   0xf9,0xf1,0x2b,0xa4,0x24,0xb7,0x75,0x7d,
                   0xe0,0x2b,0xbd,0xfb,0xae,0x0d,0x4c,0x4f,
                   0xdf,0x93,0x17,0xc8,0x0c,0xc5,0xfe,0x04,
                   0xc6,0x42,0x90,0x73,0x46,0x6c,0xf2,0x97,
                   0x06,0xb8,0xc2,0x59,0x99,0xdd,0xd2,0xf6,
                   0x54,0x0d,0x44,0x75,0xcc,0x97,0x7b,0x87,
                   0xf4,0x75,0x7b,0xe0,0x23,0xf1,0x9b,0x8f,
                   0x40,0x35,0xd7,0x72,0x28,0x86,0xb7,0x88,
                   0x69,0x82,0x6d,0xe9,0x16,0xa7,0x9c,0xf9,
                   0xc9,0x4c,0xc7,0x9c,0xd4,0x34,0x7d,0x24,
                   0xb5,0x67,0xaa,0x3e,0x23,0x90,0xa5,0x73,
                   0xa3,0x73,0xa4,0x8a,0x5e,0x67,0x66,0x40,
                   0xc7,0x9c,0xc7,0x01,0x97,0xe1,0xc5,0xe7,
                   0xf9,0x02,0xfb,0x53,0xca,0x18,0x58,0xb6};
/* function prototypes to define later */
char *do_web_request(char *url, int argc, ...);
size_t static write_callback_func(void *buffer,
						size_t size,
						size_t nmemb,
						void *userp);
inline bool ascii_incr(char *str);
inline void ascii_incr_char(char *c, bool *carry_inout);


/* select the context size and init the context */
int Skein_Init(hashState *state) {
	state->statebits = 64*SKEIN1024_STATE_WORDS;
	return Skein1024_Init(&state->u.ctx1024, 1024);
}

/* process data to be hashed */
int Skein_Update(hashState *state, const BitSequence *data, DataLength databitlen)
	{
	/* only the final Update() call is allowed do partial bytes, else assert an error */
	Skein_Assert((state->u.h.T[1] & SKEIN_T1_FLAG_BIT_PAD) == 0 || databitlen == 0, FAIL);

	if ((databitlen & 7) == 0) {
			return Skein1024_Update(&state->u.ctx1024,data,databitlen >> 3);
		}
	else
		{
		size_t bCnt = (databitlen >> 3) + 1;                  /* number of bytes to handle */
		u08b_t mask,*p;

#if (!defined(_MSC_VER)) || (MSC_VER >= 1200)                 /* MSC v4.2 gives (invalid) warning here!!  */
		Skein_assert(&state->u.h == &state->u.ctx1024.h);
#endif
		Skein1024_Update(&state->u.ctx1024,data,bCnt);
		p    = state->u.ctx1024.b;

		Skein_Set_Bit_Pad_Flag(state->u.h);                     /* set tweak flag for the final call */
		/* now "pad" the final partial byte the way NIST likes */
		bCnt = state->u.h.bCnt;         /* get the bCnt value (same location for all block sizes) */
		Skein_assert(bCnt != 0);        /* internal sanity check: there IS a partial byte in the buffer! */
		mask = (u08b_t) (1u << (7 - (databitlen & 7)));         /* partial byte bit mask */
		p[bCnt-1]  = (u08b_t)((p[bCnt-1] & (0-mask)) | mask);   /* apply bit padding on final byte (in the buffer) */

		return SUCCESS;
		}
	}

/* finalize hash computation and output the result (hashbitlen bits) */
int Skein_Final(hashState *state, BitSequence *hashval) {
	return Skein1024_Final(&state->u.ctx1024,hashval);
}


/* all-in-one hash function */
int Skein_Hash(const BitSequence *data, /* all-in-one call */
               DataLength databitlen,BitSequence *hashval)
	{
	hashState  state;
	int r = Skein_Init(&state);
	if (r == SKEIN_SUCCESS)
		{ /* these calls do not fail when called properly */
		r = Skein_Update(&state,data,databitlen);
		Skein_Final(&state,hashval);
		}
	return r;
	}

void ShowBytes(uint_t cnt,const u08b_t *b)
	{ /* formatted output of byte array */
	uint_t i;

	for (i=0;i < cnt;i++)
		{
		if (i %16 ==  0) printf("    ");
		else if (i % 4 == 0) printf(" ");
		printf(" %02X",b[i]);
		if (i %16 == 15 || i==cnt-1) printf("\n");
		}
	}

int NumberOfSetBits(int i)
{
	i = i - ((i >> 1) & 0x55555555);
	i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
	return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

int doHash(char *b,int len)
{
	u08b_t      hashVal[1028];
	uint_t      oneBlk;
	int i, diff = 0;
	oneBlk = 8*len;

	if (Skein_Hash((unsigned char *)b,oneBlk,hashVal) != SKEIN_SUCCESS)
		printf("Skein_Hash != SUCCESS");

	for(i = 0; i < 128; i++) {
		diff += NumberOfSetBits(target[i] ^ hashVal[i]);
	}

	return diff;

}


/* the function to return the content for a url */
char *do_web_request(char *url, int argc, ...)
{
    va_list argv;
    char *params[8];
	/* keeps the handle to the curl object */
	CURL *curl_handle = NULL;
	/* to keep the response */
	char *response = NULL, *c = NULL, *next = NULL;
    char request[4096];
	CURLcode error;
    int x;

    strcat(request, url);
    strcat(request, "?");

    va_start(argv, argc);
    for(x = 0; x < argc; x++) {
        // Add value name
        c = (char *) va_arg(argv, char *);
        strcat(request, c);
        strcat(request, "=");

        // Add value
        c = (char *) va_arg(argv, char *);
        next = curl_easy_escape(curl_handle, c, strlen(c));
        strcat(request, next);
        strcat(request, "?");
        curl_free(next);
    }
    va_end(argv);

	/* initializing curl and setting the url */
	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_HTTPGET, 1);

	/* follow locations specified by the response header */
	curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1);

	/* setting a callback function to return the data */
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback_func);

	/* passing the pointer to the response as the callback parameter */
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);

	/* perform the request */
	if ((error = curl_easy_perform(curl_handle)) != CURLE_OK) {
		response = NULL;
		fprintf(stderr, "Error: %d - %s\n", error, curl_easy_strerror(error));
	}

	/* cleaning all curl stuff */
	curl_easy_cleanup(curl_handle);

	return response;
}

/* the function to invoke as the data recieved */
size_t static write_callback_func(void *buffer,
                                  size_t size,
                                  size_t nmemb,
                                  void *userp)
{
	char **response_ptr =  (char**)userp;

	/* assuming the response is a string */
	*response_ptr = strndup(buffer, (size_t)(size *nmemb));

	return nmemb;
}

inline void
ascii_incr_char(char *c, bool *carry_inout)
{
	if (*carry_inout) {
		if (*c != 'z') {
			if (*c != 'Z')
				*c += 1;
			else
				*c = 'a';
			*carry_inout = false;
		} else
			*c = 'A';
	}
}

inline bool
ascii_incr(char *str)
{
	char *eos = str + strlen(str) - 1;
	bool carry = true;

	while (true) {
		ascii_incr_char(eos, &carry);

		if (eos == str && carry)
			return true;

		if (!carry)
			return false;

		eos--;
	}
}

void usage() {
	printf("usage: xkcd (target) (reporter)\n");
	printf("\ttarget - upper bound of valid hashes to output to user\n");
	printf("\treporter - reporter name for reporting a successful hash\n");
}

/*
 ./xkcd prefix target num
 target - upper bound of valid hashes to output to user
 reporter - person or machine name who reported a successful hash. Any string.
*/
int main(int argc,char *argv[])
{
	int i;
	char data[1024];
	int diff = 0;

	if (argc != 3) {
		usage();
		return 1;
	}

	int target = atoi(argv[1]);
	char *reporter = argv[2];
	//BLOCK SIZE
	int num = 50000000;
	//Request to get the block start position
	char *url = "http://crackertracker.computmaxer.net/next_block";
	char *content = NULL;

	while(true){
		content = do_web_request(url, 0);

		if (content == NULL) {
			fprintf(stderr, "Failed to contact server, trying again\n");
			continue;
		}

		strcpy(data, content);

		printf("Starting new batch of %u tries...\n", num);

		for(i = 0; i < num; i++) {
			diff = doHash(data,strlen(data));

			if(diff < target) {
				printf("%s->%d\n",data,diff);
				char buffer[4096];
                char diffStr[8];
                char url[] = "http://crackertracker.computmaxer.net/submit/";

                sprintf(diffStr, "%d", diff);

				do_web_request(url, 3, "original", data, "diff", diffStr, "submitted_by", reporter);
				target = diff;
			}
			ascii_incr(data);
		}
	}
}
