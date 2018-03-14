/*
  read-fascn.c - FASC-N Display Utility

  Usage
    read-fascn x octet1 octet2 octet3...

  must be exact number of octets

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
  main
    (int
      argc,
    char
      *argv [])

{ /* main for read-fascn.c */

  CSSH_CONFIG
    config;
  unsigned char
    fasc_n [FASCN_ARRAY];
  int
    i;
  int
    status;
  int
    value;


  status = 0;
  memset (fasc_n, 0, sizeof (fasc_n));
  if (argc != (1+sizeof (fasc_n)))
  {
    status = -1;
    fprintf (stderr, "Not enough octets (have %d need %d\n",
      argc - 2, (unsigned)sizeof (fasc_n));
  };
  if (status == 0)
  {
    for (i=0; i<(sizeof (fasc_n)-1); i++)
    {
      value = 0;
      if (i < argc)
        if (argv [2+i])
          if (strlen (argv [2+i]) > 0)
            sscanf (argv [2+i], "%x", &value);
      value = value & 0xff;
      fasc_n [i] = value;
    };
  };
  decode_fascn (&config, fasc_n);

  if (status != 0)
    fprintf (stderr, "Exit status %d\n", status);
  return (status);

} /* main for read-fascn.c */

