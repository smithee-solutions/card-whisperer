// (C)Copyright 2017-2018 Smithee Solutions LLC

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <card-whisperer.h>


int
  interpret_historical
    (CSHH_CONFIG *ctx,
    unsigned char *buffer,
    int count)

{ /* interpret_historical */

  unsigned char df_name;
  unsigned char hardware_configuration;
  unsigned char *hptr;
  unsigned char software_configuration;
  int status;


  status = ST_OK;
  df_name = 0;
  hptr = buffer;
  if (status EQUALS ST_OK)
  {
    if (*hptr EQUALS 0x80)
      status = ST_OK;
    else
    {
      status = -1;
      fprintf(stderr, "Historical byte offset %d. value %02x was not %02x\n",
        (int)(hptr-buffer), *hptr, 0x80);
    };
  };
  if (status EQUALS ST_OK)
  {
    hptr++;
    if (*hptr EQUALS 0x31)
    {
      hptr++;
      df_name = *hptr;
    }
    else
    {
      status = -2;
      fprintf(stderr, "tag 31 (direct application DF name) expected\n");
    };
  };
  if (status EQUALS ST_OK)
  {
    hptr++;
    if (*hptr EQUALS 0x52)
    {
      hptr++;
      hardware_configuration = *hptr;
    }
    else
    {
      status = -3;
      fprintf(stderr, "tag 52 (Card Issuer Data) expected\n");
    };
  };
  if (status EQUALS ST_OK)
  {
    hptr++;
    software_configuration = *hptr;

  };
  if (status EQUALS ST_OK)
  {
    printf ("  DF name %02x\n", df_name);
    printf ("  Hardware Configuration: Oberthur ID-One Cosmo V8 R2\n");
    if ((software_configuration & 0xF0) EQUALS 0x10)
    {
      printf ("  Appl AID: PIV\n");
    }
    else
    {
      if ((software_configuration & 0xF0) EQUALS 0x20)
      {
        printf ("  Appl AID: Derived PIV\n");
      }
      else
      {
        printf ("  Appl AID: Unknown (%x)\n", (software_configuration & 0xF0) >> 8);
      };
    };
    if ((software_configuration & 0x08) EQUALS 0x08)
    {
      printf("  xIV Config: NPIVP\n");
    }
    else
    {
      printf("  xIV Config: CIV\n");
    };
    if ((hardware_configuration EQUALS 0x11) && ((software_configuration & 0x03) EQUALS 0))
      printf("  Applet verison 2.3.5\n");
    if ((hardware_configuration EQUALS 0x11) && ((software_configuration & 0x01) EQUALS 1))
      printf("  Applet verison 2.4.0\n");
  };
  return (status);

} /* interpret_historical */
