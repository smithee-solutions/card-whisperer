/*
  cssh-chuid.c - CHUID processing routines for card-whisperer

  (C)Copyright 2017-2018 Smithee Solutions LLC

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  portions based on Ludovic Rousseau's blog post
    http://ludovicrousseau.blogspot.com/2010/04/pcsc-sample-in-c.html
*/

#include <stdio.h>
#include <string.h>
#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>


extern unsigned char
  fasc_n_buf_in [CSHH_FASCN_PAD_MAX];
extern unsigned char
  fasc_n_buf_out [CSHH_FASCN_PAD_MAX];
unsigned char
  fasc_n_bcd_lookup [10] =
  {
    0x01,0x10,0x08,0x19,0x04,0x15,0x0D,0x1C,0x02,0x13
  };
extern int
  global_verbosity;


int
  chuid_add
    (CSHH_CHUID_ITEM
      *chuid_items,
    int
      *item_index,
    int
      item_type,
    char
      *contents)

{ /* chuid_add */

  int
    status;


  status = ST_OK;
  if (global_verbosity > 3)
    fprintf (stderr, "item add: idx before %d type %d\n",
      *item_index, item_type);
  if (*item_index < 0)
    status = ST_CSHH_BAD_CHUID_INDEX;
  if (*item_index > (CSHH_MAX_CHUID_ITEMS-1))
    status = ST_CSHH_CHUID_LIST_FULL;
  if (status EQUALS ST_OK)
  {
    chuid_items [*item_index].item_type = item_type;
    strcpy ((char *)chuid_items [*item_index].string_value, contents);
    (*item_index)++;
  };
  return (status);

} /* chuid_add */


int
  cshh_build_fascn
    (CSHH_STOMPER_CONFIG
      *cfg,
    CSHH_FASC_N
      *fasc_n,
    unsigned char
      *raw_fascn)

{ /* cshh_build_fascn */

  int
    i;
  int
    status;
int shifted_bits;


shifted_bits=0;
  status = ST_OK;
  if (fasc_n != NULL)
  {
    memset (fasc_n_buf_in, 0, CSHH_FASCN_PAD_MAX);
    memset (fasc_n_buf_out, 0, CSHH_FASCN_PAD_MAX);


    // shift in FASCN_FIELD_SS
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
    status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
shifted_bits = shifted_bits + 5;
    fasc_n_buf_in [24] = fasc_n_buf_in [24] | FASCN_FIELD_SS;

    // shift in 4 digits of agency
    for (i=0; (i<sizeof(fasc_n->agency)) & (status EQUALS ST_OK); i++)
    {
      status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
      memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
      fasc_n_buf_in [24] = fasc_n_buf_in [24] |
        fasc_n_bcd_lookup [fasc_n->agency [i] - '0'];
    };

    // shift in FS
    status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
    fasc_n_buf_in [24] = fasc_n_buf_in [24] | FASCN_FIELD_FS;

    // shift in 4 digits of system code
    for (i=0; (i<sizeof(fasc_n->system)) & (status EQUALS ST_OK); i++)
    {
      status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
      memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
      fasc_n_buf_in [24] = fasc_n_buf_in [24] |
        fasc_n_bcd_lookup [fasc_n->system [i] - '0'];
    };

    // shift in FS
    status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
    fasc_n_buf_in [24] = fasc_n_buf_in [24] | FASCN_FIELD_FS;

    // shift in 6 digits of credential
    for (i=0; (i<sizeof(fasc_n->credential)) & (status EQUALS ST_OK); i++)
    {
      status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
      memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
      fasc_n_buf_in [24] = fasc_n_buf_in [24] |
        fasc_n_bcd_lookup [fasc_n->credential [i] - '0'];
    };

    // shift in FS
    status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
    fasc_n_buf_in [24] = fasc_n_buf_in [24] | FASCN_FIELD_FS;

    // shift in CS
    status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
    fasc_n_buf_in [24] = fasc_n_buf_in [24] |
      fasc_n_bcd_lookup [fasc_n->cs [0] - '0'];

    // shift in FS
    status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
    fasc_n_buf_in [24] = fasc_n_buf_in [24] | FASCN_FIELD_FS;

    // shift in ICI
    status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
    fasc_n_buf_in [24] = fasc_n_buf_in [24] |
      fasc_n_bcd_lookup [fasc_n->ici [0] - '0'];

    // shift in FS
    status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
    fasc_n_buf_in [24] = fasc_n_buf_in [24] | FASCN_FIELD_FS;

    // shift in PI
    for (i=0; (i<sizeof(fasc_n->pi)) & (status EQUALS ST_OK); i++)
    {
      status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
      memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
      fasc_n_buf_in [24] = fasc_n_buf_in [24] |
        fasc_n_bcd_lookup [fasc_n->pi [i] - '0'];
    };

    // shift in OC
    status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
    fasc_n_buf_in [24] = fasc_n_buf_in [24] |
      fasc_n_bcd_lookup [fasc_n->oc [0] - '0'];

    // shift in OI
    for (i=0; (i<sizeof(fasc_n->oi)) & (status EQUALS ST_OK); i++)
    {
      status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
      memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
      fasc_n_buf_in [24] = fasc_n_buf_in [24] |
        fasc_n_bcd_lookup [fasc_n->oi [i] - '0'];
    };

    // shift in POA
    status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
    fasc_n_buf_in [24] = fasc_n_buf_in [24] |
      fasc_n_bcd_lookup [fasc_n->poa [0] - '0'];

    // shift in ES
    status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
shifted_bits = shifted_bits + 5;
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
    fasc_n_buf_in [24] = fasc_n_buf_in [24] | FASCN_FIELD_ES;

    status = cshh_shifter (fasc_n_buf_out, fasc_n_buf_in, 25, 5);
    memcpy (fasc_n_buf_in, fasc_n_buf_out, 25);
    memcpy (cfg->fascn_buffer, fasc_n_buf_in, 25);
  };

// if fasc_n null and raw_fascn not null
// load fascn from raw hex

  return (status);

} /* cshh_build_fascn */


unsigned char
  cssh_hex_to_binary
    (unsigned char
      hexit)

{ /* cssh_hex_to_binary */

  unsigned char
    binary_hexit;

  binary_hexit = 0;
  if (hexit >= '0')
    if (hexit <= '9')
      binary_hexit = hexit - '0';
  if (hexit >= 'a')
    if (hexit <= 'f')
      binary_hexit = (hexit - 'a') + 10;
  if (hexit >= 'A')
    if (hexit <= 'F')
      binary_hexit = (hexit - 'A') + 10;
  return (binary_hexit);

} /* cssh_hex_to_binary */


int
  cshh_is_digits
    (unsigned char
      *digits)

{ /* cshh_is_digits */

  int
    done;
  int
    i;
  int
    valid;
     

  done = 0;
  valid = 1;
  for (i=0; (i<strlen ((const char *)digits)) & (!done); i++)
  {
    if (digits[i] < '0')
    {
      done = 1;
      valid = 0;
    };
    if ('9' < digits[i])
    {
      done = 1;
      valid = 0;
    };
  };
  return (valid);

} /* cshh_is_digits */


int
  cshh_is_hexits
    (unsigned char
      *hexits)

{ /* cshh_is_hexits */

  int
    done;
  int
    i;
  int
    valid;
     

  done = 0;
  valid = 1;
  for (i=0; (i<strlen ((const char *)hexits)) & (!done); i++)
  {
    valid = 0;
    if (hexits[i] >= '0')
      if (hexits[i] <= '9')
      {
        valid = 1;
      };
    if (hexits[i] >= 'a')
      if (hexits[i] <= 'f')
      {
        valid = 1;
      };
    if (hexits[i] >= 'A')
      if (hexits[i] <= 'F')
      {
        valid = 1;
      };
    if (!valid)
      done = 1;
  };
  return (valid);

} /* cshh_is_hexits */

