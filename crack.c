#include <curl/curl.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "skein.h"

char *do_web_request(char *url);
size_t static write_callback_func(void *buffer, size_t size, size_t nmemb, void *userp);
inline bool ascii_incr(char *str);
inline void ascii_incr_char(char *c, bool *carry_inout);


int NumberOfSetBits(uint64_t c) 
{
	/* 64-bit method */
	static const uint64_t S[] = {1,2,4,8,16,32};
	static const uint64_t B[] = {0x5555555555555555,
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


/* the function to return the content for a url */
char *do_web_request(char *url) 
{
	/* keeps the handle to the curl object */
	CURL *curl_handle = NULL;
	/* to keep the response */
	char *response = NULL;
	CURLcode error;

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


inline void ascii_incr_char(char *c, bool *carry_inout)
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


inline bool ascii_incr(char *str)
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


void usage() 
{
	printf("usage: xkcd (target) (reporter)\n");
	printf("\ttarget - upper bound of valid hashes to output to user\n");
	printf("\treporter - reporter name for reporting a successful hash\n");
}


/*
 ./xkcd prefix target num
 target - upper bound of valid hashes to output to user (auto decrements)
 reporter - person or machine name who reported a successful hash. Any string.
*/
int main(int argc,char *argv[])
{
	int i = 0;
	char data[33];
	int diff = 0;
	char buffer[4096];
	uint64_t hashVal[16];
	uint64_t match[] = 
	{
		0x8082a05f5fa94d5b,0xc818f444df7998fc,0x7d75b724a42bf1f9,0x4f4c0daefbbd2be0,
		0x04fec50cc81793df,0x97f26c46739042c6,0xf6d2dd9959c2b806,0x877b97cc75440d54,
		0x8f9bf123e07b75f4,0x88b7862872d73540,0xf99ca716e96d8269,0x247d34d49cc74cc9,
		0x73a590233eaa67b5,0x4066675e8aa473a3,0xe7c5e19701c79cc7,0xb65818ca53fb02f9
	};
	int target     = 512;
	char *reporter = "Unknown";

	if (argc != 3) {
		usage();
		return -1;
	}

	target   = atoi(argv[1]);
	reporter = argv[2];
	
	/* set random prefix */
	srand(time(NULL) * getpid());
	for (i=0; i<32; i++) {
		data[i] = (rand() % 26) + 65;
	}
	data[32] = 0;

	printf("Starting with a prefix of:\n%s\n", data);

	while(true){
		HashSkein1024((const uint8_t *) data, strlen(data), (uint8_t *) hashVal);

		diff = 0;
		for(i = 0; i < 16; i++) {
			diff += NumberOfSetBits(match[i] ^ hashVal[i]);
		}

		if(diff < target) {
			printf("%s->%d\n", data, diff);

			snprintf(buffer, sizeof(buffer), "http://crackertracker.computmaxer.net/submit/?original=%s&diff=%d&submitted_by=%s", data, diff, reporter);
			printf("%s\n", do_web_request(buffer));

			target = diff;

			if (target == 0) return 0; /* win! */
		}

		ascii_incr(data);
	}
}
