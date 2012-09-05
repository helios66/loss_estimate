/*
 *  Code adapted from Crypto-PAN 1.0 Code. See original disclaimer below
 *	The sourcecode has been converted from C++ to C and adapted for nfdump
 *
 *  Copyright (c) 2004, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  $Author: peter $
 *
 *  $Id: panonymizer.c 70 2006-05-17 08:38:01Z peter $
 *
 *  $LastChangedRevision: 70 $
 *	
 */

/* Original disclaimer
 * Atlanta, Georgia 30332.
 * All Rights Reserved
 * 
 * The following Software is posted on the Internet by the Georgia
 * Tech Research Corporation (GTRC). It was developed by employees
 * of the Georgia Institute of Technology in the College of Computing.
 * GTRC hereby grants to the user a non-exclusive, royalty-free
 * license to utilize such Software for the User's own purposes
 * pursuant to the following conditions.
 * 
 * 
 * THE SOFTWARE IS LICENSED ON AN "AS IS" BASIS. GTRC MAKES NO WARRANTY
 * THAT ALL ERRORS CAN BE OR HAVE BEEN ELIMINATED FROM THE SOFTWARE.
 * GTRC SHALL NOT BE RESPONSIBLE FOR LOSSES OF ANY KIND RESULTING FROM
 * THE USE OF THE SOFTWARE AND ITS ACCOMPANYING DOCUMENTATION, AND CAN 
 * IN NO WAY PROVIDE COMPENSATION FOR ANY LOSSES SUSTAINED, INCLUDING 
 * BUT NOT LIMITED TO ANY OBLIGATION, LIABILITY, RIGHT, CLAIM OR REMEDY 
 * FOR TORT, OF FOR ANY ACTUAL OR ALLEGED INFRINGEMENT OF PATENTS, COPYRIGHTS,
 * TRADE SECRETS, OR SIMILAR RIGHTS OF THIRD PARTIES, NOR ANY BUSINESS 
 * EXPENSE, MACHINE DOWNTIME, OR DAMAGES CAUSED LICENSEE BY ANY DEFICIENCY,
 * DEFECT OR ERROR IN THE SOFTWARE OR MALFUNCTION THEREOF, NOR ANY 
 * INCIDENTAL OR CONSEQUENTIAL DAMAGES, HOWEVER CAUSED. GTRC DISCLAIMS
 * ALL WARRANTIES, BOTH EXPRESS AND IMPLIED RESPECTING THE USE AND
 * OPERATION OF THE SOFTWARE AND ANY ACCOMPANYING DOCUMENTATION,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * PARTICULAR PURPOSE AND ANY IMPLIED WARRANTY ARISING FROM COURSE
 * OF PERFORMANCE, COURSE OF DEALING OR USAGE OF TRADE. GTRC MAKES NO
 * WARRANTY THAT THE SOFTWARE IS ADEQUATELY OR COMPLETELY DESCRIBED 
 * IN, OR BEHAVES IN ACCORDANCE WITH ANY OF THE ACCOMPANYING 
 * DOCUMENTATION. THE USER OF THE SOFTWARE IS EXPECTED TO MAKE THE FINAL
 * EVALUATION OF THE SOFTWARE'S USEFULNESS IN USER'S OWN ENVIRONMENT.
 * 
 *
 * Package: Crypto-PAn 1.0
 * File: panonymizer.cpp
 * Last Update: April 17, 2002
 * Author: Jinliang Fan
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>


#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "panonymizer.h"

// Init
void PAnonymizer_Init(panon_t *instance,uint8_t * key) {
  //initialize the 128-bit secret key.
  memcpy(instance->m_key, key, 16);
  //initialize the Rijndael cipher. 
  Rijndael_init(&instance->rinst,ECB, Encrypt, key, Key16Bytes, NULL);
  //initialize the 128-bit secret pad. The pad is encrypted before being used for padding.
  Rijndael_blockEncrypt(&instance->rinst,key + 16, 128, instance->m_pad);  
}

//Anonymization funtion
uint32_t anonymize(panon_t *instance,const uint32_t orig_addr) {
    uint8_t rin_output[16];
    uint8_t rin_input[16];

    uint32_t result = 0;
    uint32_t first4bytes_pad, first4bytes_input;
    int pos;

    memcpy(rin_input, instance->m_pad, 16);
    first4bytes_pad = (((uint32_t) instance->m_pad[0]) << 24) + (((uint32_t) instance->m_pad[1]) << 16) +
	(((uint32_t) instance->m_pad[2]) << 8) + (uint32_t) instance->m_pad[3]; 

    // For each prefixes with length from 0 to 31, generate a bit using the Rijndael cipher,
    // which is used as a pseudorandom function here. The bits generated in every rounds
    // are combineed into a pseudorandom one-time-pad.
    for (pos = 0; pos <= 31 ; pos++) { 

	//Padding: The most significant pos bits are taken from orig_addr. The other 128-pos 
        //bits are taken from m_pad. The variables first4bytes_pad and first4bytes_input are used
	//to handle the annoying byte order problem.
	if (pos==0) {
	  first4bytes_input =  first4bytes_pad; 
	}
	else {
	  first4bytes_input = ((orig_addr >> (32-pos)) << (32-pos)) | ((first4bytes_pad<<pos) >> pos);
	}
	rin_input[0] = (uint8_t) (first4bytes_input >> 24);
	rin_input[1] = (uint8_t) ((first4bytes_input << 8) >> 24);
	rin_input[2] = (uint8_t) ((first4bytes_input << 16) >> 24);
	rin_input[3] = (uint8_t) ((first4bytes_input << 24) >> 24);

	//Encryption: The Rijndael cipher is used as pseudorandom function. During each 
	//round, only the first bit of rin_output is used.
	Rijndael_blockEncrypt(&instance->rinst,rin_input, 128, rin_output);	

	//Combination: the bits are combined into a pseudorandom one-time-pad
	result |=  (rin_output[0] >> 7) << (31-pos);
    }
    //XOR the orginal address with the pseudorandom one-time-pad
    return result ^ orig_addr;
}

/* little endian CPU's are boring! - but give it a try
 * orig_addr is a ptr to memory, return by inet_pton for IPv6
 * anon_addr return the result in the same order
 */
void anonymize_v6(panon_t *instance,const uint64_t orig_addr[2], uint64_t *anon_addr) {
    uint8_t rin_output[16], *orig_bytes, *result;
    uint8_t rin_input[16];

    int pos, i, bit_num, left_byte;

	anon_addr[0] = anon_addr[1] = 0;
	result 		 = (uint8_t *)anon_addr;
	orig_bytes 	 = (uint8_t *)orig_addr;

    // For each prefixes with length from 0 to 127, generate a bit using the Rijndael cipher,
    // which is used as a pseudorandom function here. The bits generated in every rounds
    // are combineed into a pseudorandom one-time-pad.
    for (pos = 0; pos <= 127 ; pos++) { 
		bit_num = pos & 0x7;
		left_byte = (pos >> 3);
		
		for ( i=0; i<left_byte; i++ ) {
			rin_input[i] = orig_bytes[i];
		}
		rin_input[left_byte] = orig_bytes[left_byte] >> (7-bit_num) << (7-bit_num) | (instance->m_pad[left_byte]<<bit_num) >> bit_num;
		for ( i=left_byte+1; i<16; i++ ) {
			rin_input[i] = instance->m_pad[i];
		}

		//Encryption: The Rijndael cipher is used as pseudorandom function. During each 
		//round, only the first bit of rin_output is used.
		Rijndael_blockEncrypt(&instance->rinst,rin_input, 128, rin_output);	

		//Combination: the bits are combined into a pseudorandom one-time-pad
		result[left_byte] |= (rin_output[0] >> 7) << bit_num;

    }
    //XOR the orginal address with the pseudorandom one-time-pad
	anon_addr[0] ^= orig_addr[0];
	anon_addr[1] ^= orig_addr[1];

}
