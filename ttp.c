#include <stdio.h>
#include <string.h>
#include <time.h>
#if z80
#include <conio.h>
#endif
#include "ttp.h"

uint8_t *hmackey;


int main(int argc, char *argv[]){
    size_t len;
    size_t keylen;
    long_type tm;
    uint8_t last_tm;
    char* newCode;
    long_type cnt = 0;
    
    /*
    printf("long %lu\n",sizeof(long_type));
    printf("size_t %lu\n",sizeof(size_t));
    printf("uint8_t %lu\n",sizeof(uint8_t));
    printf("uint32_t %lu\n",sizeof(uint32_t));
    */
    
    
    switch(argc){
      case 2:
         hmackey = (uint8_t *)argv[1];
         break;
      default:
         printf("Usage: %s <b32_key>\n", argv[0]);
         return(1);
    }
    len = strlen(argv[1]);
    
    if (((len & 0xF) != 0) && ((len & 0xF) != 8)){
      printf("%s: invalid base32 secret\n", argv[0]);
      return(1);
    }

    keylen = decode_base32(hmackey);
    	
    tm = (time(NULL) / 30);
    
	last_tm = (uint8_t )tm + 1;    
    
    while(cnt<80000000){ 
        cnt++;
		tm = time(NULL) / 30;
#if z80		      
        /* TIME CORRECT FOR z80 CPM3.0 */
        tm = tm - (long_type)360;
#endif        
        
        
#if z80		  
        if(kbhit()){
            printf("%u \n",getchar());
          
        }
#endif        
		if( (uint8_t )tm != last_tm ){
			last_tm = (uint8_t )tm;
			newCode = getCode(hmackey, keylen, tm);
			printf("totp: %s\n",newCode);
		}
        
    }    


	
	return 0;
}