/*
  decode-atr.c - ATR decoding routines for card whisperer

  (C)Copyright 2017-2018 Smithee Solutions LLC
*/


#include <memory.h>
#include <stdio.h>

#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>



int
  display_atr
    (CSSH_CONFIG
      *ctx,
    unsigned char
      *buffer,
    int
      lth)

{ /* display_atr */

  int
    atr_historical_count;
  int
    atr_length;
  unsigned char
    atr_t0;
  unsigned char
    atr_ta1;
  int
    atr_ta1_present;
  int
    atr_tc1_present;
  int
    atr_td1_present;
  int
    atr_td2_present;
  unsigned char
    atr_tc1;
  unsigned char
    atr_td1;
  unsigned char
    atr_td2;
  unsigned char
    atr_ts;
  unsigned char
    *atrptr;
  int
    i;
  unsigned char
    *raw_atr;
  int
    status;


  status = 0;
  raw_atr = buffer;
  atr_length = lth;
  atr_tc1 = 0;
  atr_td2 = 0;
  atr_ta1_present = 0;
  atr_tc1_present = 0;
  atr_td1_present = 0;
  atr_td2_present = 0;
  atr_historical_count = 0;
  fprintf (stderr, "Raw ATR: ");
  for (i=0; i<atr_length; i++)
  {
    fprintf (stderr, " %02x",
      raw_atr [i]);
  };
  fprintf (stderr, "\n");

  // ATR is <TS> <T0> [<TA>] [<TB>] [<TC>] ...
  atrptr = raw_atr;
  atr_ts = *atrptr; atrptr++;
  atr_t0 = *atrptr; atrptr++;
  atr_historical_count = 0x0f & atr_t0; // T0 low nybble is historical count
  if (0x10 & atr_t0) //fifth bit
  {
    atr_ta1_present = 1;
    atr_ta1 = *atrptr; atrptr++;
  };
  if (0x40 & atr_t0) //seventh bit
  {
    atr_tc1_present = 1;
    atr_tc1 = *atrptr; atrptr++;
  };
  if (0x80 & atr_t0) //eighth bit
  {
    atr_td1_present = 1;
    atr_td1 = *atrptr; atrptr++;
  };

  printf ("TS %02x",
    atr_ts);
  printf (" T0 %02x",
    atr_t0);
  if (atr_ta1_present)
    printf (" TA1 %02x",
      atr_ta1);
  if (atr_tc1_present)
    printf (" TC1 %02x",
      atr_tc1);
  if (atr_td1_present)
    printf (" TD1 %02x",
      atr_td1);
  printf ("\n");

  if (atr_ts == 0x3b)
    printf ("  Card operating according to 'direct' convention\n");

  // parse bits in T0
  if (atr_ta1_present)
  {
    printf ("  T0 bit 5 set\n");
  };
  if (0x20 & atr_t0)
    printf ("  T0 bit 6 set\n");
  if (0x40 & atr_t0)
    printf ("  T0 bit 7 set\n");
  if (0x80 & atr_t0)
    printf ("  T0 bit 8 set\n");
  printf ("  %d. historical bytes\n",
    atr_historical_count);

  // parse bits in TA1
  if (atr_ta1_present)
  {
    char *di_tags [] ={
      "RFU(0)",
      "1",
      "2",
      "4",
      "8",
      "16",
      "32",
      "64",
      "12",
      "20",
      "RFU(A)",
      "RFU(B)",
      "RFU(C)",
      "RFU(D)",
      "RFU(E)",
      "RFU(F)" };
    char *fmax_tags[]={
      "Fi=372, fMAX 4",
      "Fi=372, fMAX 5",
      "Fi=558, fMAX 6",
      "Fi=744, fMAX 8",
      "Fi=1116, fMAX 12",
      "Fi=1488, fMAX 16",
      "Fi=1860, fMAX 20",
      "RFU(7)",
      "RFU(8)",
      "Fi=512, fMAX 5",
      "Fi=768, fMAX 7.5",
      "Fi=1024, fMAX 10",
      "Fi=1536, fMAX 15",
      "Fi=2048, fMAX 20",
      "RFU(E)",
      "RFU(F)"
      };
    printf ("  Di= %s\n", di_tags [atr_ta1 & 0x0f]);
    printf ("  %s\n", fmax_tags [(atr_ta1 & 0xf0)>>4]);
  };

  // parse bits in TC1
  printf ("  Extra Guard Time: %d\n", atr_tc1);

  // parse bits in TD1
  if (atr_td1_present)
  {
    if ((atr_td1 & 0x0f) == 0)
      printf ("  Protocol: T0\n");
    if ((atr_td1 & 0x0f) == 1)
      printf ("  Protocol: T1\n");
    if (atr_td1 & 0x80)
    {
      atr_td2_present = 1;
      atr_td2 = *atrptr; atrptr++;
    };
  };

  if (atr_td2_present)
    printf (" TD2 %02x",
      atr_td2);

  if (atr_historical_count > 0)
  {
    int i;

    memcpy (ctx->historical_bytes, atrptr, atr_historical_count);
    ctx->historical_count = atr_historical_count;
    printf("\n  Historical Bytes:");
    for(i=0; i<atr_historical_count; i++)
    {
      printf(" %02x ", *(atrptr+i));
    };
  };
  printf ("\n");

  return (status);

} /* display_atr */

