#include <stdio.h>

typedef struct _pcap_file_header{

#define MAGIC   0xa1b2c3d4 //pcap magic

    int magic;
    unsigned short version_major;
    unsigned short version_minor;
    int thiszone; /* gmt to localcorrection */
    unsigned sigfigs; /* accuracy oftimestamps */
    unsigned snaplen;            /* maxlength savedportion of each pkt */
    unsigned linktype;            /* datalink type (LINKTYPE_*) */

}pcap_file_header;

