// based on https://github.com/lucadentella/TOTP-Arduino

#include <stdio.h>
#include <string.h>
#include <time.h>
//#include <math.h>
//#include <stdint.h>

#include "ttp.h"


uint8_t *hmackey;


int main(int argc, char *argv[]){	
	 switch(argc){
      case 2:
      	hmackey  = (uint8_t *)argv[1];
      break;

      default:
      	fprintf(stderr, "Usage: %s <b32_key>\n", argv[0]);
      return(1);
      break;
     };

	 size_t len = strlen(argv[1]);
	
	
	 //decode BASE32
	 
    // validates base32 key
    if (((len & 0xF) != 0) && ((len & 0xF) != 8)){
      fprintf(stderr, "%s: invalid base32 secret\n", argv[0]);
      return(1);
    };

    size_t keylen = decode_base32(hmackey);
	
    char* newCode = getCode(hmackey, keylen, time(NULL));
	
    printf("totp: %s\n",newCode);	
	
	return 0;	
}


