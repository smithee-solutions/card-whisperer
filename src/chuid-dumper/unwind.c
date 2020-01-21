#include <stdio.h>
#include <string.h>

#define EQUALS ==

typedef struct cw_chuid
{
  int front_parity;
  int agency;
  int system;
  long credential;
  long expiration;
  int rear_parity;
} CW_CHUID;


int chuid_bits [1024];
int verbosity = 3;


void
  bytes_to_bits
    (char *hex,
    int *bits)

{
  int done;
  int i;
  int j;
  int nybble;
  int octet;


  memset(bits, 0, 75);
  done = 0;
  nybble = 0;
  octet = 0;
  i = 0;
  j = 0;
  while (!done)
  {
    // upper nybble

    if (hex[i] >= '0')
      if (hex[i] <= '9')
        nybble = hex[i] - '0';
    if (hex[i] >= 'A')
      if (hex[i] <= 'F')
        nybble = 10 + hex[i] - 'A';
    if (hex[i] >= 'a')
      if (hex[i] <= 'f')
        nybble = 10 + hex[i] - 'a';
    octet = nybble << 4;
    i++;

    // lower nybble

    nybble = 0;
    if (hex[i] >= '0')
      if (hex[i] <= '9')
        nybble = hex[i] - '0';
    if (hex[i] >= 'A')
      if (hex[i] <= 'F')
        nybble = 10 + hex[i] - 'A';
    if (hex[i] >= 'a')
      if (hex[i] <= 'f')
        nybble = 10 + hex[i] - 'a';
    octet = octet | nybble;

    if (0x80 & octet) bits [j] = 1; j++;
    if (0x40 & octet) bits [j] = 1; j++;
    if (0x20 & octet) bits [j] = 1; j++;
    if (0x10 & octet) bits [j] = 1; j++;
    if (0x08 & octet) bits [j] = 1; j++;
    if (0x04 & octet) bits [j] = 1; j++;
    if (0x02 & octet) bits [j] = 1; j++;
    if (0x01 & octet) bits [j] = 1; j++;
    i++;

    if (j >= 75)
      done = 1;
    if (verbosity > 3)
      fprintf(stderr, "DEBUG: bit %2d octet %02x\n",
  j, octet);
  };

}

int
  unwind_piv_75bit
    (char *chuid_75bit_hex,
    CW_CHUID *chuid)

{

  int i;
  int next_bit;


  next_bit = 0;
  memset(chuid, 0, sizeof(*chuid));
  bytes_to_bits(chuid_75bit_hex, chuid_bits);
  printf("Bits:\n");
  for(i=0; i<75; i++)
  {
    printf(" %d", chuid_bits [i]);
    if (7 EQUALS (i%8))
      printf("\n");
  };
  printf("\n");
  chuid->front_parity = chuid_bits [next_bit];
  next_bit++;

  for (i=0; i<14; i++)
  {
    chuid->agency = chuid->agency << 1;
    if (chuid_bits [next_bit + i])
      chuid->agency = chuid->agency + 1;
  };
  next_bit = next_bit + 14;

  for (i=0; i<14; i++)
  {
    chuid->system = chuid->system << 1;
    if (chuid_bits [next_bit + i])
      chuid->system = chuid->system + 1;
  };
  next_bit = next_bit + 14;

  for (i=0; i<20; i++)
  {
    chuid->credential = chuid->credential << 1;
    if (chuid_bits [next_bit + i])
      chuid->credential = chuid->credential + 1;
    if (verbosity > 3)
      fprintf(stderr, "DEBUG: credential(%2d) %ld\n", i, chuid->credential);
  };
  next_bit = next_bit + 20;

  for (i=0; i<25; i++)
  {
    chuid->expiration = chuid->expiration << 1;
    if (chuid_bits [next_bit + i])
      chuid->expiration = chuid->expiration + 1;
  };
  next_bit = next_bit + 25;

  chuid->rear_parity = chuid_bits [next_bit];

  return (0);

}


int
  main
    (int argc,
    char *argv [])

{
  CW_CHUID chuid;
  char chuid_hex [1024];
  int i;
  int next;


#if 0
  1 bit even parity (over what?)
  14 bits agency code
  14 bits system code
  20 bits card number
  25 bits expiration yyyymmdd
  1 bit odd parity
#endif
  strcpy(chuid_hex, argv [1]);
  printf("CHUID (hex): %s\n", chuid_hex);
  (void)unwind_piv_75bit(chuid_hex, &chuid);

  printf("f Agency         System         Credential           Expiration                r\n");
  next = 0;
  printf("%d", chuid_bits [0]);
  printf(" ");
  next++;

  for (i=0; i<14; i++)
    printf("%d", chuid_bits [next+i]);
  printf(" ");
  next = next + 14;

  for (i=0; i<14; i++)
    printf("%d", chuid_bits [next+i]);
  printf(" ");
  next = next + 14;

  for (i=0; i<20; i++)
    printf("%d", chuid_bits [next+i]);
  printf(" ");
  next = next + 20;

  for (i=0; i<25; i++)
    printf("%d", chuid_bits [next+i]);
  printf(" ");
  next = next + 25;

  printf("%d", chuid_bits [next]);

  printf("\n");

  printf("CHUID (75 bit format):\n");
  printf("  Front Parity: %d\n", chuid.front_parity);
  printf("  Agency: %d. (%04x)\n", chuid.agency, chuid.agency);
  printf("  System: %d. (%04x)\n", chuid.system, chuid.system);
  printf("  Credential: %ld. (%lx)\n", chuid.credential, chuid.credential);
  printf("  Expiration: %ld. (%lx)\n", chuid.expiration, chuid.expiration);
  printf("  Rear Parity: %d\n", chuid.rear_parity);
  return(0);
}

