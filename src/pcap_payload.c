/*---------------------------------------------------------------------------------------------
--	SOURCE FILE:	proc_payload.c - Set of function to process and print the packet payload
--
--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
--					filter (BPF)
--
--	DATE:			May 10, 2023
--
--	REVISIONS:		(Date and nic_description)
--	DATE:			May 15, 2023
--				    Added personal function for assignment
--
--	DESIGNERS:		Based on the code by Martin Casado, Aman Abdulla
--				    Modified & redesigned: Aman Abdulla: May 4, 2016
--
--	STUDENT:		HyungJoon LEE
-------------------------------------------------------------------------------------------------*/

#include "spoof.h"


char cwd[100] = {0};

// This function will print payload data
void print_payload (const u_char *payload, int len) {

	int len_rem = len;
	int line_width = 16;		// number of bytes per line
	int line_len;
	int offset = 0;			// offset counter 
	const u_char *ch = payload;

	if (len <= 0)
		return;

	// does data fits on one line?
	if (len <= line_width) {
		print_hex_ascii_line (ch, len, offset);
		return;
	}

	// data spans multiple lines
	for ( ;; ) {
		// determine the line length and print
		line_len = line_width % len_rem;
		print_hex_ascii_line (ch, line_len, offset);

        // Process the remainder of the line
		len_rem -= line_len;
		ch += line_len;
		offset += line_width;

        // Ensure we have line width chars or less
		if (len_rem <= line_width) {
			//print last line
			print_hex_ascii_line (ch, len_rem, offset);
			break;
		}
	}
}


// Print data in hex & ASCII
void print_hex_ascii_line (const u_char *payload, int len, int offset) {

	int i;
	const u_char *ch;
    char temp[1024] = {0};


	// print in hex 
    ch = payload;
    for (i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        if (i == 7)
            printf(" ");
    }


    // print spaces to handle a line size of less than 8 bytes
    if (len < 8)
        printf(" ");


    // Print ASCII
    ch = payload;
    for (i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf ("\n");
}


