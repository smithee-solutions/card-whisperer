/*
  cardcalc - calculate card formats from a hex string

  (C)Copyright 2019 Smithee Solutions LLC

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include <stdio.h>
#include <memory.h>
#include <getopt.h>


#define VERSION_STRING_CARDCALC "0.02-1"
#define CARDCALC_MAX_OCTETS (1024)
#define CARDCALC_MAX_BITS (8*CARDCALC_MAX_OCTETS)

#define CARDCALC_OPT_NOOP      ( 0)
#define CARDCALC_OPT_HEX       ( 1)
#define CARDCALC_OPT_FORMAT    ( 2)
#define CARDCALC_OPT_HELP      ( 3)
#define CARDCALC_OPT_VERBOSITY ( 4)
#define CARDCALC_FMT_UNKNOWN     ( 0)
#define CARDCALC_FMT_26BIT       ( 1)
#define CARDCALC_FMT_CORP1000_48 ( 2)

typedef struct cardcalc_context
{
  int bits;
  int card_format;
  char format_name [1024];
  int verbosity;
  char mask_1_odd_parity [1024];
} CARDCALC_CONTEXT;

#define EQUALS ==
#define ST_OK (0)


int option;
struct option longopts [] = {
  {"format", required_argument, &option, CARDCALC_OPT_FORMAT},
  {"help", 0, &option, CARDCALC_OPT_HELP},
  {"hex", required_argument, &option, CARDCALC_OPT_HEX},
  {"verbosity", required_argument, &option, CARDCALC_OPT_VERBOSITY},
  {0, 0, 0, 0}};

char * cardcalc_mask (CARDCALC_CONTEXT *ctx, char *bitstring, char *mask);
int cardcalc_parity_odd(CARDCALC_CONTEXT *ctx, char *data_string,
  char *parity_mask);

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

{ /* cardcalc_bits_to_decimal */

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
      if (ctx->verbosity > 9)
        fprintf(stderr, "DEBUG: value 0x%lx %lu.\n", value, value);
    };
    if (index > strlen(bitstring))
      done = 1;
    index++;
  };
  return(value);

} /* cardcalc_bits_to_decimal */


int
  cardcalc_display_card
    (CARDCALC_CONTEXT *ctx,
    char *whole_binary_string)

{ /* cardcalc_display_card */

  char cardholder_mask [CARDCALC_MAX_BITS+1];
  unsigned long int ch;
  char facility_code_mask [CARDCALC_MAX_BITS+1];
  unsigned long int fc;
  int parity_1_odd;
  int status;


  status = ST_OK;
  parity_1_odd = 0;

  if (ctx->card_format EQUALS CARDCALC_FMT_CORP1000_48)
  {
    ctx->bits = 48;
    strcpy(ctx->mask_1_odd_parity,
      "000110011011011011000000000000000000000000000000");
    strcpy(ctx->format_name, "Corporate 1000 48 Bit");
  };

  if (ctx->verbosity > 3)
    fprintf(stderr, "Card bits: %d.\n", ctx->bits);
  fprintf(stdout,
"  Card format: %s\n", ctx->format_name);
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
    if (strlen(ctx->mask_1_odd_parity) > 0)
    {
      fprintf(stdout,
" Parity (odd): %s\n",
        ctx->mask_1_odd_parity);
    };
    fprintf(stdout,
"          Raw: %s\n", whole_binary_string);
    fprintf(stdout, 
"Facility Code: %s\n",
  cardcalc_mask(ctx, whole_binary_string, facility_code_mask));
    fprintf(stdout, 
"   Cardholder: %s\n",
  cardcalc_mask(ctx, whole_binary_string, cardholder_mask));

fprintf(stdout,
"               12345678----++++12345678----++++12345678----++++\n");
fprintf(stdout,
"               000000000011111111112222222222333333333344444444\n");
fprintf(stdout,
"               012345678901234567890123456789012345678901234567\n");

    if (strlen(ctx->mask_1_odd_parity) > 0)
      parity_1_odd = cardcalc_parity_odd(ctx,
        whole_binary_string, ctx->mask_1_odd_parity);
    fprintf(stdout,
" Parity=%d (Odd) with mask %s\n",
      parity_1_odd, ctx->mask_1_odd_parity);

    fc = cardcalc_bits_to_decimal(ctx, 
      cardcalc_mask(ctx, whole_binary_string, facility_code_mask)),
    ch = cardcalc_bits_to_decimal(ctx,
      cardcalc_mask(ctx, whole_binary_string, cardholder_mask));
    fprintf(stdout, "FC %lu.(0x%08lx) CH %lu.(0x%08lx)\n",
      fc, fc, ch, ch);
    break;
  };
  return(status);

} /* cardcalc_display_card */


char *
  cardcalc_mask
    (CARDCALC_CONTEXT *ctx,
    char *bitstring,
    char *mask)

{ /* cardcalc_mask */

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
  if (ctx->verbosity > 3)
    fprintf(stdout, "DEBUG: mask size %d\n", mask_size);
  return(result);

} /* cardcalc_mask */

int
  cardcalc_parity_odd
    (CARDCALC_CONTEXT *ctx,
    char *data_string,
    char *parity_mask)

{ /* cardcalc_parity_odd */

  int i;
  int mask_length;
  int returned_parity;


  returned_parity = 0;
  mask_length = strlen(parity_mask);
  if (ctx->verbosity > 3)
    fprintf(stderr, "DEBUG: calc odd parity lth %d.\n", mask_length);
  for (i=0; i<mask_length; i++)
  {
    if (parity_mask [i] EQUALS '1')
    {
      if (data_string [i] EQUALS '1')
      {
        if (ctx->verbosity > 3)
          fprintf(stderr, "Parity calc idx %02d mask %c value %c\n",
            i, parity_mask [i], data_string [i]);
        returned_parity++;
      };
    };
  };
  returned_parity = returned_parity & 0x01;
  return(returned_parity);

} /* cardcalc_parity_odd */


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
      fprintf(stderr, "  --format=[ 26BIT | CORP1000-48 ]\n");
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
      case CARDCALC_OPT_VERBOSITY:
        {
          int v;
          sscanf(optarg, "%d", &v);
          ctx->verbosity = v;
          if (ctx->verbosity > 3)
            fprintf(stderr, "Verbosity set to %d.\n", ctx->verbosity);
        };
        break;
      };
    };
    if (status != ST_OK)
      done = 1;
  };

  fprintf(stdout, "cardcalc %s\n", VERSION_STRING_CARDCALC);
  if (ctx->verbosity > 3)
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
    if (ctx->verbosity > 9)
      fprintf(stdout, "Octet %02d. is hex %02x binary %s\n",
        i,  data_string [data_index], binary_string(data_string [data_index]));
    data_index ++;
  };

  status = cardcalc_display_card(ctx, whole_binary_string);

  if (status != ST_OK)
    fprintf(stderr, "cardcalc exit, status %d\n", status);
  return (status);

} /* main for cardcalc */

