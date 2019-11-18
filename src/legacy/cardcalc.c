/*
  cardcalc - calculate card formats from a hex string
*/

#include <stdio.h>
#include <memory.h>
#include <getopt.h>


#define VERSION_STRING_CARDCALC "0.00-EP01"
#define CARDCALC_MAX_OCTETS (1024)
#define CARDCALC_MAX_BITS (8*CARDCALC_MAX_OCTETS)

#define CARDCALC_OPT_NOOP   ( 0)
#define CARDCALC_OPT_HEX    ( 1)
#define CARDCALC_OPT_FORMAT ( 2)
#define CARDCALC_OPT_HELP   ( 3)
#define CARDCALC_FMT_UNKNOWN     ( 0)
#define CARDCALC_FMT_26BIT       ( 1)
#define CARDCALC_FMT_CORP1000_48 ( 2)

typedef struct cardcalc_context
{
  int bits;
  int card_format;
  int verbosity;
} CARDCALC_CONTEXT;

#define EQUALS ==
#define ST_OK (0)


int option;
struct option longopts [] = {
  {"format", required_argument, &option, CARDCALC_OPT_FORMAT},
  {"hex", required_argument, &option, CARDCALC_OPT_HEX},
  {"help", 0, &option, CARDCALC_OPT_HELP},
  {0, 0, 0, 0}};
char * cardcalc_mask (char *bitstring, char *mask);

char *
  binary_string
    (unsigned char octet)

{ /* binary_string */

  static char bitstring [9];


  memset(bitstring, 0x30, sizeof(bitstring));
  bitstring [sizeof(bitstring)-1] = 0;
  if (octet & 0x80) bitstring [0] = '1';
  if (octet & 0x40) bitstring [1] = '1';
  if (octet & 0x20) bitstring [2] = '1';
  if (octet & 0x10) bitstring [3] = '1';
  if (octet & 0x08) bitstring [4] = '1';
  if (octet & 0x04) bitstring [5] = '1';
  if (octet & 0x02) bitstring [6] = '1';
  if (octet & 0x01) bitstring [7] = '1';
  return(bitstring);

} /* binary_string */


unsigned long int
  cardcalc_bits_to_decimal
    (CARDCALC_CONTEXT *ctx,
    char *bitstring)

{
  int done;
  int index;
  unsigned long int value;


  value = 0;
  done = 0;
  index =0;
  while (!done)
  {
    if (bitstring [index] != ' ')
    {
      value = value << 1;
      if (bitstring [index] EQUALS '1')
        value = value + 1;
      if (ctx->verbosity > 3)
        fprintf(stderr, "DEBUG: value 0x%lx %lu.\n", value, value);
    };
    if (index > strlen(bitstring))
      done = 1;
    index++;
  };
  return(value);
}


int
  cardcalc_display_card
    (CARDCALC_CONTEXT *ctx,
    char *whole_binary_string)

{ /* cardcalc_display_card */

  char cardholder_mask [CARDCALC_MAX_BITS+1];
  char facility_code_mask [CARDCALC_MAX_BITS+1];
  int status;


  status = ST_OK;
  if (ctx->card_format EQUALS CARDCALC_FMT_CORP1000_48)
    ctx->bits = 48;

  if (ctx->verbosity > 3)
    fprintf(stderr, "Card bits: %d.\n", ctx->bits);
  switch(ctx->card_format)
  {
  default:
    fprintf(stderr, "Unknown format (%d)\n", ctx->card_format);
    break;
  case CARDCALC_FMT_CORP1000_48:
//fprintf(stderr, "DEBUG: Poooooooooooooooo\n");
//fprintf(stderr, "DEBUG: -P?ee?ee?ee?ee?ee\n");
//fprintf(stderr, "DEBUG: --oo-oo-oo-oo-oo-\n");

//fprintf(stderr, "010000000001000101100101000011100010001001000011\n");
//fprintf(stderr, "010000000001000101100101000011100010001001000011\n");
//fprintf(stderr, "                           01110001000101000001\n");
//fprintf(stderr, "        0001000101100101\n");
    strcpy(facility_code_mask,
"001111111111111111111111000000000000000000000000");
    strcpy(cardholder_mask,
"000000000000000000000000111111111111111111111110");
    fprintf(stdout,
"          Raw: %s\n", whole_binary_string);
    fprintf(stdout, 
"Facility Code: %s\n", cardcalc_mask(whole_binary_string, facility_code_mask));
    fprintf(stdout, 
"   Cardholder: %s\n", cardcalc_mask(whole_binary_string, cardholder_mask));

fprintf(stderr,
"               12345678----++++12345678----++++12345678----++++\n");
fprintf(stderr,
"               000000000011111111112222222222333333333344444444\n");
fprintf(stderr,
"               012345678901234567890123456789012345678901234567\n");

    fprintf(stdout, "FC %lu CH %lu\n",
      cardcalc_bits_to_decimal(ctx, cardcalc_mask(whole_binary_string, facility_code_mask)),
      cardcalc_bits_to_decimal(ctx, cardcalc_mask(whole_binary_string, cardholder_mask)));
    break;
  };
  return(status);
}


char *
  cardcalc_mask
    (char *bitstring,
    char *mask)

{
  int idx;
  int mask_size;
  static char result [CARDCALC_MAX_BITS+1];


  mask_size = 0;
  for (idx=0; idx<strlen(bitstring); idx++)
  {
    result [idx] = ' ';
    if (mask [idx] EQUALS '1')
    {
      mask_size++;
      result [idx] = bitstring [idx];
    };
  };
fprintf(stdout, "DEBUG: mask size %d\n", mask_size);
  return(result);
}


int
  main
    (int argc,
    char *argv [])

{ /* main for cardcalc */

  CARDCALC_CONTEXT card_context;
  CARDCALC_CONTEXT *ctx;
  int data_index;
  unsigned char data_string [1024];
  int done;
  int found_something;
  char hex_string [1025];
  int i;
  int length;
  char optstring [CARDCALC_MAX_OCTETS*2 + 1];
  int status;
  int status_opt;
  unsigned int temp_octet;
  char temp_octet_string [4];
  char whole_binary_string [1+CARDCALC_MAX_BITS];


  ctx = &card_context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->bits = 26;

  ctx->verbosity = 3;
ctx->verbosity=9;
  status = ST_OK;
  strcpy(hex_string, "1234abcd");
  done = 0;
  found_something = 0;
  option = CARDCALC_OPT_NOOP;
  ctx->card_format = CARDCALC_FMT_26BIT;
  while (!done)
  {
    status_opt = getopt_long (argc, argv, optstring, longopts, NULL);
    if (ctx->verbosity > 3)
      fprintf(stderr, "getopt_long: %d optarg %s \n", status_opt, optarg);
    if (status_opt EQUALS -1)
    {
      done = 1;
    };
    if (!done) 
    {
      switch (option)
    {
    default:
      fprintf(stderr, "Unknown switch\n");
      break;
    case CARDCALC_OPT_HELP:
      fprintf(stderr, "  --format\n");
      fprintf(stderr, "  --hex\n");
      break;
    case CARDCALC_OPT_NOOP:
      break;
    case CARDCALC_OPT_FORMAT:
      ctx->card_format = CARDCALC_FMT_UNKNOWN;
      if (strcmp(optarg, "CORP1000-48") EQUALS 0)
        ctx->card_format = CARDCALC_FMT_CORP1000_48;
      break;
    case CARDCALC_OPT_HEX:
      strcpy(hex_string, optarg);
      break;
    };
    };
    if (status != ST_OK)
      done = 1;
  };

  fprintf(stdout, "cardcalc %s\n", VERSION_STRING_CARDCALC);
  fprintf(stderr, "card format: %d.\n", ctx->card_format);
  fprintf(stdout,
"      Raw Hex: %s\n", hex_string);

  length = strlen(hex_string)/2;
  if ((2*length) != strlen(hex_string))
    fprintf(stderr, "Warning: string not an even number of hexits.\n");
  data_index = 0;
  memset(whole_binary_string, 0, sizeof(whole_binary_string));
  for (i=0; i<length; i++)
  {
    memcpy(temp_octet_string, hex_string+(2*i), 2);
    temp_octet_string [2] = 0;
    sscanf(temp_octet_string, "%x", &temp_octet);
    data_string [data_index] = temp_octet;
    strcat(whole_binary_string, binary_string(data_string [data_index]));
    if (ctx->verbosity > 3)
      fprintf(stdout, "Octet %02d. is hex %02x binary %s\n",
        i,  data_string [data_index], binary_string(data_string [data_index]));
    data_index ++;
  };

  status = cardcalc_display_card(ctx, whole_binary_string);

  if (status != ST_OK)
    fprintf(stderr, "cardcalc exit, status %d\n", status);
  return (status);

} /* main for cardcalc */
