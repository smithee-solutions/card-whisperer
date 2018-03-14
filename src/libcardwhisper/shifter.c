// (C)Copyright 2017-2018 Smithee Solutions LLC

#include <stdio.h>
#include <string.h>


#define EQUALS ==

extern int
  global_verbosity;

int
  cshh_shifter
    (unsigned char
      *dest,
    unsigned char
      *source,
    int
      octet_length,
    int
      bit_count)

{ /* shifter */

  int
    i;
  int
    j;
  unsigned char 
    isource [25+1];
  int
    new_bit;
  unsigned char
    new_octet;
  int
    status;


  status = 0;
if (global_verbosity > 9)
{
 int q;
  fprintf (stderr, " orig: ");
  for (q=0; q<octet_length; q++)
    fprintf (stderr, "%02x", source[q]);
  fprintf (stderr, "\n");
};
  memcpy (isource, source, sizeof (isource));
  isource [sizeof (isource)-1] = 0;
  if (status EQUALS 0)
  {
    for (i=0; i<bit_count; i++)
    {
      for (j=0; j<octet_length; j++)
      {
        new_bit = (isource[j+1]) & 0x80;
        new_octet = 0x7f & (isource [j]);
        if (new_bit != 0)
        {
          new_octet = (new_octet << 1) | 1;
        }
        else
        {
          new_octet = new_octet << 1;
        };
        isource [j] = new_octet;
      };
if (global_verbosity > 9)
{
 int q;
  fprintf (stderr, "shft%d: ", 1+i);
  for (q=0; q<octet_length; q++)
    fprintf (stderr, "%02x", isource[q]);
  fprintf (stderr, "\n");
};
    };
  };
  memcpy (dest, isource, 25);
  return (status);
} /* shifter */

#ifdef TEST
int
  main
    (int
      argc,
    char
      *argv [])
{

  unsigned char
    dest [25];
  unsigned char
    source [25] =
      { 0x00, 0xf0, 0xcc, 0x10, 
        0x0F, 0x01, 0x01, 0x00, 
        0x01, 0x01, 0x01, 0x00, 
        0x01, 0x01, 0x01, 0x00, 
        0x01, 0x01, 0x01, 0x00, 
        0x01, 0x01, 0x01, 0x01, 
        0xff };
  int
    status;


  status = shifter (dest, source, 25, 5);

  return (status);
}

#endif

