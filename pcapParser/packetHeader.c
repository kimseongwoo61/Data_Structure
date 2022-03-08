#include <stdio.h>
#include "infoTime.c"

typedef struct _pcap_header
{
    timeval ts;    /*time stamp */
    unsigned caplen; /* length of portionpresent */
    unsigned len;     /*length thispacket (off wire) */
}pcap_header;
