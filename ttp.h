/* based on https://github.com/lucadentella/TOTP-Arduino */

#include <stdint.h>

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c
#if z80
/* #define uint32_t unsigned long */
/* #define uint8_t unsigned char */
/* #define uint64_t unsigned long long */
/* #define int32_t int */
/* #define size_t unsigned long */

#define ulong_type unsigned long
#define long_type long

#else

#define ulong_type unsigned int
#define long_type int
#define size_t short

#endif

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

#define SHA1_K0 0x5a827999
#define SHA1_K20 0x6ed9eba1
#define SHA1_K40 0x8f1bbcdc
#define SHA1_K60 0xca62c1d6

uint8_t sha1InitState[] = {
  0x01,0x23,0x45,0x67, /* H0 */
  0x89,0xab,0xcd,0xef, /* H1 */
  0xfe,0xdc,0xba,0x98, /* H2 */
  0x76,0x54,0x32,0x10, /* H3 */
  0xf0,0xe1,0xd2,0xc3  /* H4 */
};

union _buffer {
  uint8_t b[BLOCK_LENGTH];
  uint32_t w[BLOCK_LENGTH/4];
} buffer;

union _state {
  uint8_t b[HASH_LENGTH];
  uint32_t w[HASH_LENGTH/4];
} state;

uint32_t byteCount;
uint8_t keyBuffer[BLOCK_LENGTH];
uint8_t innerHash[HASH_LENGTH];
uint8_t bufferOffset;

uint8_t* _hmacKey;
int _keyLength;
uint8_t _byteArray[8];
uint8_t* _hash;
int _offset;
char _code[7];


union test_u {
   struct test_s {
      unsigned char b0;
      unsigned char b1;
      unsigned char b2;
      unsigned char b3;
   } bytes;
   ulong_type ullong;
} lpack;





void init(void);
uint32_t rol32(uint32_t number, uint8_t bits);
void hashBlock();
void addUncounted(uint8_t data);
void s_write(uint8_t data);
void pad();
uint8_t* rresult(void);
void initHmac(uint8_t* key, int keyLength);
uint8_t* resultHmac(void);


char* getCode(uint8_t* hmacKey, int keyLength, long_type steps);

uint8_t decode_base32(uint8_t* key);

/*    This map cheats and interprets:
       - the numeral zero as the letter "O" as in oscar
       - the numeral one as the letter "L" as in lima
       - the numeral eight as the letter "B" as in bravo
   00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
*/
static int8_t base32_vals[256] =
{
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 0x00 */
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 0x10 */
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 0x20 */
   14, 11, 26, 27, 28, 29, 30, 31,  1, -1, -1, -1, -1,  0, -1, -1,  /* 0x30 */
   -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  /* 0x40 */
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,  /* 0x50 */
   -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  /* 0x60 */
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1,  /* 0x70 */
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 0x80 */
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 0x90 */
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 0xA0 */
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 0xB0 */
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 0xC0 */
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 0xD0 */
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 0xE0 */
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 0xF0 */
};



void init(void){
	memcpy(state.b,sha1InitState,HASH_LENGTH);
  	byteCount = 0;
  	bufferOffset = 0;
}

uint32_t rol32(uint32_t number, uint8_t bits) {
  return ((number << bits) | (number >> (32-bits)));
}


void hashBlock() {
  uint8_t i;
  uint32_t a,b,c,d,e,t;

  a=state.w[0];
  b=state.w[1];
  c=state.w[2];
  d=state.w[3];
  e=state.w[4];
  for (i=0; i<80; i++) {
    if (i>=16) {
      t = buffer.w[(i+13)&15] ^ buffer.w[(i+8)&15] ^ buffer.w[(i+2)&15] ^ buffer.w[i&15];
      buffer.w[i&15] = rol32(t,1);
    }
    if (i<20) {
      t = (d ^ (b & (c ^ d))) + SHA1_K0;
    } else if (i<40) {
      t = (b ^ c ^ d) + SHA1_K20;
    } else if (i<60) {
      t = ((b & c) | (d & (b | c))) + SHA1_K40;
    } else {
      t = (b ^ c ^ d) + SHA1_K60;
    }
    t+=rol32(a,5) + e + buffer.w[i&15];
    e=d;
    d=c;
    c=rol32(b,30);
    b=a;
    a=t;
  }
  state.w[0] += a;
  state.w[1] += b;
  state.w[2] += c;
  state.w[3] += d;
  state.w[4] += e;
}


void addUncounted(uint8_t data) {
  buffer.b[bufferOffset ^ 3] = data;
  bufferOffset++;
  if (bufferOffset == BLOCK_LENGTH) {
    hashBlock();
    bufferOffset = 0;
  }
}


void s_write(uint8_t data) {
  ++byteCount;
  addUncounted(data);
}


void pad() {
  /* Implement SHA-1 padding (fips180-2 ยง5.1.1)
     Pad with 0x80 followed by 0x00 until the end of the block 
  */
  addUncounted(0x80);
  while (bufferOffset != 56) addUncounted(0x00);
  /* Append length in the last 8 bytes */
  addUncounted(0); /* We're only using 32 bit lengths */
  addUncounted(0); /* But SHA-1 supports 64 bit lengths */
  addUncounted(0); /* So zero pad the top bits */
  addUncounted(byteCount >> 29); /* Shifting to multiply by 8 */
  addUncounted(byteCount >> 21); /* as SHA-1 supports bitstreams as well as */
  addUncounted(byteCount >> 13); /* byte. */
  addUncounted(byteCount >> 5);
  addUncounted(byteCount << 3);
}




uint8_t* rresult(void) {
  /* Pad to complete the last block */
  int i;
  pad();
  /* Swap byte order back */
  for(i=0;i<5;i++){
    uint32_t a,b;
    a=state.w[i];
    b=a<<24;
    b|=(a<<8) & 0x00ff0000;
    b|=(a>>8) & 0x0000ff00;
    b|=a>>24;
    state.w[i]=b;
  }
  /* Return pointer to hash (20 characters) */
  return state.b;
}


void initHmac(uint8_t* key, int keyLength) {
  uint8_t i;
  memset(keyBuffer,0,BLOCK_LENGTH);
  if (keyLength > BLOCK_LENGTH) {
    /* Hash long keys */
    init();
    for (;keyLength--;) s_write(*key++);
    memcpy(keyBuffer,rresult(),HASH_LENGTH);
  } else {
    /* Block length keys are used as is */
    memcpy(keyBuffer,key,keyLength);
  }
  /* Start inner hash */
  init();
  for (i=0; i<BLOCK_LENGTH; i++) {
    s_write(keyBuffer[i] ^ HMAC_IPAD);
  }
}



uint8_t* resultHmac(void) {
  uint8_t i;
  /* Complete inner hash */
  memcpy(innerHash,rresult(),HASH_LENGTH);
  /* Calculate outer hash */
  init();
  for (i=0; i<BLOCK_LENGTH; i++) s_write(keyBuffer[i] ^ HMAC_OPAD);
  for (i=0; i<HASH_LENGTH; i++) s_write(innerHash[i]);
  return rresult();
}

/* get totp function; 
   Args: 
	 	hmackKey - decoded key in byte array; 
		keyLength - the length of the key inside the array, because after the decoding base32 function works,
					the key remains in the same array, and its length is less than the length of the array. 
					The end of key in the array is the element with the value 0.
		steps - current Unix time
*/
char* getCode(uint8_t* hmacKey, int keyLength, long_type steps) {
	int j;
	_hmacKey = hmacKey;
	_keyLength = keyLength;
  
  
  /* STEP 0, map the number of steps in a 8-bytes array (counter value) */
	_byteArray[0] = 0x00;
	_byteArray[1] = 0x00;
	_byteArray[2] = 0x00;
	_byteArray[3] = 0x00;
	_byteArray[4] = (int)((steps >> 24) & 0xFF);
	_byteArray[5] = (int)((steps >> 16) & 0xFF);
	_byteArray[6] = (int)((steps >> 8) & 0XFF);
	_byteArray[7] = (int)((steps & 0xFF));
  
  /* STEP 1, get the HMAC-SHA1 hash from counter and key */
	initHmac(_hmacKey, _keyLength);
	for(j=0; j<8; j++){
		s_write(_byteArray[j]);
	}
	_hash = resultHmac();
  
	/* STEP 2, apply dynamic truncation to obtain a 4-bytes string */
  _offset = _hash[20 - 1] & 0xF; 
  
  lpack.ullong = 0;
  lpack.bytes.b3 = (_hash[_offset]   & 0x7f);
  lpack.bytes.b2 = (_hash[_offset+1] & 0xff);
  lpack.bytes.b1 = (_hash[_offset+2] & 0xff);
  lpack.bytes.b0 = (_hash[_offset+3] & 0xff);
  
  /* STEP 3, compute the OTP value */
  lpack.ullong %= 1000000;
#if z80
	sprintf(_code, "%06ld", lpack.ullong);
#else
  sprintf(_code, "%06d", lpack.ullong);
#endif
	return _code;
}


/*  Function decode base32 array, returns length of "key" inside of "key array". 
    Length of array > length of key!
    The value of element of array after last key element is _0_
  
    Key array after work of function:
  		AA AA AA AA AA AA 00 05 BB AA
  		|___________________________| - length of all array
  		|__________________|		  - length of key - result of function
*/
uint8_t decode_base32(uint8_t* key){    
  size_t pos;
  size_t keylen = 0;
  /*
  size_t i;
  
  size_t ms = strlen((char *)key);
  */

  for(pos = 0; pos <= (strlen((char *)key) - 8); pos += 8){
      /* MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
         MB is middle bits             (0x7E == 01111110 ~= MB)
         LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)
      */
      /* byte 0 */
    
    key[keylen+0]  = ((base32_vals[key[pos+0]] << 3) & 0xF8) | ((base32_vals[key[pos+1]] >> 2) & 0x07);
	  key[keylen+1]  = ((base32_vals[key[pos+1]] << 6) & 0xC0) | ((base32_vals[key[pos+2]] << 1) & 0x3E) | ((base32_vals[key[pos+3]] >> 4) & 0x01);
	  key[keylen+2]  = ((base32_vals[key[pos+3]] << 4) & 0xF0) | ((base32_vals[key[pos+4]] >> 1) & 0x0F);
	  key[keylen+3]  = ((base32_vals[key[pos+4]] << 7) & 0x80) | ((base32_vals[key[pos+5]] << 2) & 0x7C) | ((base32_vals[key[pos+6]] >> 3) & 0x03);
	  key[keylen+3]  = ((base32_vals[key[pos+4]] << 7) & 0x80) | ((base32_vals[key[pos+5]] << 2) & 0x7C) | ((base32_vals[key[pos+6]] >> 3) & 0x03);
	  key[keylen+4]  = ((base32_vals[key[pos+6]] << 5) & 0xE0) | ((base32_vals[key[pos+7]] >> 0) & 0x1F);	   
      if (key[pos+2] == '='){
          keylen += 1;
          break;
      };
    /* byte 1 */
      if (key[pos+4] == '='){
          keylen += 2;
          break;
      };
    /* byte 2 */
      if (key[pos+5] == '='){
          keylen += 3;
          break;
      };
    /* byte 3 */
      if (key[pos+7] == '='){
          keylen += 4;
          break;
      };
    /* byte 4 */
      keylen += 5;
   };
   key[keylen] = 0;
  
   /* returns length of key, not length of key array */
   return keylen;
}