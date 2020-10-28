
#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0')

  void f(uint32_t address)  {
     printf("m: "BYTE_TO_BINARY_PATTERN" "BYTE_TO_BINARY_PATTERN" "BYTE_TO_BINARY_PATTERN" "BYTE_TO_BINARY_PATTERN"\n",
     BYTE_TO_BINARY(address>>24), BYTE_TO_BINARY(address>>16), BYTE_TO_BINARY(address>>8), BYTE_TO_BINARY(address));}


void printhex(packet p){
     
    char * temp = p.payload;

    for(int i=1; i <= p.len; i++){
        printf("%x", (unsigned char) *temp);
        temp ++;
        if(i%2 == 0) printf(" ");
        if(i%16 == 0) printf(".........\n");
    }
    printf("\n");
}