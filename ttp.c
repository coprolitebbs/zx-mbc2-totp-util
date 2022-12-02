#include <stdio.h>
#include <string.h>
#include <time.h>
/* #include <signal.h> */
#include "ttp.h"

uint8_t *hmackey;

/*
void intHandler(int dummy) {
    signal(dummy, SIG_IGN);
    printf("exiting\n");
    exit(0);
}
*/


int main(int argc, char *argv[]){
    size_t len;
    size_t keylen;
    long_type tm;
    uint8_t last_tm;
    char* newCode;
    char *tk = "VKVKVKVK";
    long_type cnt = 0;
    
    printf("long %lu\n",sizeof(long_type));
    printf("size_t %lu\n",sizeof(size_t));
    printf("uint8_t %lu\n",sizeof(uint8_t));
    printf("uint32_t %lu\n",sizeof(uint32_t));
    
    
    /*    
    signal(SIGINT, intHandler);
    */
    
    switch(argc){
      case 2:
         hmackey = (uint8_t *)argv[1];
         break;
      default:
         /* hmackey = (uint8_t *)tk;    */
         printf("Usage: %s <b32_key>\n", argv[0]);
         return(1);
	 /* break; */
    }
    len = strlen(/* argv[1] */tk);
    
    if (((len & 0xF) != 0) && ((len & 0xF) != 8)){
      printf("%s: invalid base32 secret\n", argv[0]);
      return(1);
    }

    keylen = decode_base32(hmackey);
    
	
    tm = time(NULL) / 30;
    
	last_tm = (uint8_t )tm + 1;
    while(cnt<8000000){ 
        cnt++;
		tm = time(NULL) / 30;
		/* if(kbhit()) return 0; */
		if( (uint8_t )tm != last_tm ){
			last_tm = (uint8_t )tm;
			newCode = getCode(hmackey, keylen, tm);
			printf("totp: %s\n",newCode);
		}
    
    }    


	
	return 0;
}