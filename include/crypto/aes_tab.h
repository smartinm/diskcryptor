#ifndef _AES_TAB_
#define _AES_TAB_

#ifndef SMALL_CODE
 extern u32 calign Te0[256];
 extern u32 calign Te1[256];
 extern u32 calign Te2[256];
 extern u32 calign Te3[256];
 
 extern u32 calign Te4_1[256];
 extern u32 calign Te4_2[256];
 extern u32 calign Te4_3[256];
 extern u32 calign Te4_4[256];

 extern u32 calign Td0[256];
 extern u32 calign Td1[256];
 extern u32 calign Td2[256];
 extern u32 calign Td3[256];

 extern u32 calign Td4_1[256];
 extern u32 calign Td4_2[256];
 extern u32 calign Td4_3[256];
 extern u32 calign Td4_4[256];
#endif /* SMALL_CODE */

#ifdef AES_ASM_1
 extern u32 *rel_tab[];
#endif

#endif /* _AES_TAB_ */