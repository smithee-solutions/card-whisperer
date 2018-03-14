/*
  decode-fascn.c - FASC-N decode routines

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


int
  decode_fascn
    (CSSH_CONFIG
      *cfg,
    unsigned char
      fasc_n [FASCN_ARRAY])

{ /* decode_fascn */

  // FASC-N Contents
  // (these are all 1024 character and treated as strings, initialized to 0
  char
    fasc_n_agency_code [1024];
  char
    fasc_n_system_code [1024];
  char
    fasc_n_credential_number [1024];
  char
    fasc_n_credential_series [1024];
  char
    fasc_n_ici [1024];
  char
    fasc_n_pi [1024];
  char
    fasc_n_oc [1024];
  char
    fasc_n_oi [1024];
  char
    fasc_n_poa [1024];

  int
    bits_left;
  int
    digit_index;
  int
    done;
  char
    *fasc_n_digit;
  int
    fascn_size;
  int
    i;
  int
    index;
  unsigned char
    left_mask;
  unsigned char
    nybble_values [1024];
  unsigned char
    right_mask;
  char
    unknown_byte [1024];
  unsigned int
    value;


  fasc_n_agency_code [0] = 0;
  fasc_n_credential_number [0] = 0;
  fasc_n_credential_series [0] = 0;
  fasc_n_ici [0] = 0;
  fasc_n_oc [0] = 0;
  fasc_n_oi [0] = 0;
  fasc_n_pi [0] = 0;
  fasc_n_poa [0] = 0;
  fasc_n_system_code [0] = 0;

  memset (nybble_values, 0, sizeof (nybble_values));

  fascn_size = FASCN_ARRAY - 1; // we add 1 byte padding
  fprintf (stderr, "FASC-N:\n");
  for (i=0; i < fascn_size; i++)
  {
    fprintf (stderr, " %02x", fasc_n [i]);
  };
  fprintf (stderr, "\n");
  fprintf (stderr, "Decoded FASC-N (5 bit values):\n");
  index = 0;
  for (i=0; i<2*fascn_size; i=i+2)
  {
    nybble_values [i] = (0xf0 & fasc_n [index]) >> 4;
    nybble_values [i+1] = (0x0f & fasc_n [index]);
    index ++;
  };

  bits_left = 8 * fascn_size;
  done = 0;
  i = 0;
  digit_index = 0;
  while (!done)
  {
    if (cfg->verbosity > 3)
      fprintf (stderr, "%d. bits left\n", bits_left);
    if (bits_left > 4)
    {
      if (0 == (digit_index % 4))
      {
        left_mask = 0xf; right_mask = 0x8;
        value = ((nybble_values [i] & left_mask) << 1) + ((nybble_values [i+1] & right_mask) >> 3);
      };
      if (1 == (digit_index % 4))
      {
        left_mask = 0x7; right_mask = 0xC;
        value = ((nybble_values [i] & left_mask) << 2) + ((nybble_values [i+1] & right_mask) >> 2);
      };

      if (2 == (digit_index % 4))
      {
        left_mask = 0x3; right_mask = 0xE;
        value = ((nybble_values [i] & left_mask) << 3) + ((nybble_values [i+1] & right_mask) >> 1);
      };
      if (3 == (digit_index % 4))
      {
        left_mask = 0x1; right_mask = 0xF;
        value = ((nybble_values [i] & left_mask) << 4) + (nybble_values [i+1] & right_mask);
      };
      if (cfg->verbosity > 9)
        fprintf (stderr, "left %02x right %02x i %02d. ni %02x ni1 %02x\n",
          left_mask, right_mask, i, nybble_values [i], nybble_values [i+1]);

      if (cfg->verbosity > 3)
        fprintf (stderr, "Packed BCD Character %2d.: %02x...", digit_index, value);
      switch (value)
      {
      default: sprintf (unknown_byte, "?-%02x", value); fasc_n_digit = unknown_byte; break;
      case 0x01: fasc_n_digit = "0"; break;
      case 0x02: fasc_n_digit = "8"; break;
      case 0x04: fasc_n_digit = "4"; break;
      case 0x08: fasc_n_digit = "2"; break;
      case 0x0D: fasc_n_digit = "6"; break;
      case 0x10: fasc_n_digit = "1"; break;
      case 0x13: fasc_n_digit = "9"; break;
      case 0x15: fasc_n_digit = "5"; break;
      case 0x16: fasc_n_digit = "FS"; break;
      case 0x19: fasc_n_digit = "3"; break;
      case 0x1A: fasc_n_digit = "SS"; break;
      case 0x1C: fasc_n_digit = "7"; break;
      case 0x1F: fasc_n_digit = "ES"; break;
      };

      // digit 0 is SS (start marker)

      // digits 1-4 are AGENCY CODE
      if (digit_index > 0)
        if (digit_index < 5)
          strcat (fasc_n_agency_code, fasc_n_digit);

      // digit 5 is FS (field separator)

      // digits 6-9 are SYSTEM CODE
      if (digit_index > 5)
        if (digit_index < 10)
          strcat (fasc_n_system_code, fasc_n_digit);

      // digit 10 is FS

      // digits 11-16 are CREDENTIAL NUMBER
      if (digit_index > 10)
        if (digit_index < 17)
          strcat (fasc_n_credential_number, fasc_n_digit);

      // digit 17 is FS

      // digits 18 is CREDENTIAL SERIES
      if (digit_index == 18)
        strcat (fasc_n_credential_series, fasc_n_digit);

      // digit 19 is FS

      // digit 20 is INDIVIDUAL CREDENTIAL ISSUE
      if (digit_index == 20)
        strcat (fasc_n_ici, fasc_n_digit);

      // digit 21 is FS

      // digits 22-31 are PERSON IDENTIFIER
      if (digit_index > 21)
        if (digit_index < 32)
          strcat (fasc_n_pi, fasc_n_digit);

      // digit 32 is ORGANIZATIONAL CATEGORY
      if (digit_index == 32)
        strcat (fasc_n_oc, fasc_n_digit);

      // digits 33-36 are PERSON IDENTIFIER
      if (digit_index > 32)
        if (digit_index < 37)
          strcat (fasc_n_oi, fasc_n_digit);

      // digit 37 is PERSON/ORGANIZATION ASSOCIATION CATEGORY
      if (digit_index == 37)
        strcat (fasc_n_poa, fasc_n_digit);

      if (cfg->verbosity > 3)
        fprintf (stderr, " CHARACTER: %s\n",
          fasc_n_digit);
      else
        fprintf (stderr, " %s",
          fasc_n_digit);
    };
    if (bits_left < 5)
      done = 1;
    bits_left = bits_left - 5;
    i++;
    if (right_mask == 0x0f)
      i++;  // already burned next nybble so increment twice
    digit_index ++;
  };

  fprintf (stderr, "\n");
  fprintf (stdout,
"      Agency Code: %s\n", fasc_n_agency_code);
  fprintf (stdout,
"      System Code: %s\n", fasc_n_system_code);
  fprintf (stdout,
"Credential Number: %s\n", fasc_n_credential_number);
  fprintf (stdout,
"Credential Series: %s\n", fasc_n_credential_series);
  fprintf (stdout,
"              ICI: %s\n", fasc_n_ici);
  fprintf (stdout,
"               PI: %s\n", fasc_n_pi);
  fprintf (stdout,
"               OC: %s\n", fasc_n_oc);
  fprintf (stdout,
"               OI: %s\n", fasc_n_oi);
  fprintf (stdout,
"              POA: %s\n", fasc_n_poa);

  return (0);
}

