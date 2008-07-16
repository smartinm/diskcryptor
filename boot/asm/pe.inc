
struct IMAGE_DOS_HEADER
  e_magic     dw ?
  e_cblp      dw ?
  e_cp	      dw ?
  e_crlc      dw ?
  e_cparhdr   dw ?
  e_minalloc  dw ?
  e_maxalloc  dw ?
  e_ss	      dw ?
  e_sp	      dw ?
  e_csum      dw ?
  e_ip	      dw ?
  e_cs	      dw ?
  e_lfarlc    dw ?
  e_ovno      dw ?
  e_res       rw 4
  e_oemid     dw ?
  e_oeminfo   dw ?
  e_res2      rw 10
  e_lfanew    dd ?
ends

struct IMAGE_FILE_HEADER
  Machine	       dw ?
  NumberOfSections     dw ?
  TimeDateStamp        dd ?
  PointerToSymbolTable dd ?
  NumberOfSymbols      dd ?
  SizeOfOptionalHeader dw ?
  Characteristics      dw ?
ends


struct IMAGE_DATA_DIRECTORY
  VirtualAddress       dd ?
  Size		       dd ?
ends


struct IMAGE_OPTIONAL_HEADER
  ; Standard fields.
  Magic 		      dw ?
  MajorLinkerVersion	      db ?
  MinorLinkerVersion	      db ?
  SizeOfCode		      dd ?
  SizeOfInitializedData       dd ?
  SizeOfUninitializedData     dd ?
  AddressOfEntryPoint	      dd ?
  BaseOfCode		      dd ?
  BaseOfData		      dd ?
  ; NT additional fields.
  ImageBase		      dd ?
  SectionAlignment	      dd ?
  FileAlignment 	      dd ?
  MajorOperatingSystemVersion dw ?
  MinorOperatingSystemVersion dw ?
  MajorImageVersion	      dw ?
  MinorImageVersion	      dw ?
  MajorSubsystemVersion       dw ?
  MinorSubsystemVersion       dw ?
  Win32VersionValue	      dd ?
  SizeOfImage		      dd ?
  SizeOfHeaders 	      dd ?
  CheckSum		      dd ?
  Subsystem		      dw ?
  DllCharacteristics	      dw ?
  SizeOfStackReserve	      dd ?
  SizeOfStackCommit	      dd ?
  SizeOfHeapReserve	      dd ?
  SizeOfHeapCommit	      dd ?
  LoaderFlags		      dd ?
  NumberOfRvaAndSizes	      dd ?
  ExportDirectory    IMAGE_DATA_DIRECTORY
  ImportDirectory    IMAGE_DATA_DIRECTORY
  ResourceDirectory  IMAGE_DATA_DIRECTORY
  ExceptionDirectory IMAGE_DATA_DIRECTORY
  SecurityDirectory  IMAGE_DATA_DIRECTORY
  RelocDirectory     IMAGE_DATA_DIRECTORY
ends


struct IMAGE_NT_HEADERS
  Signature	 dd ?
  FileHeader	 IMAGE_FILE_HEADER
  OptionalHeader IMAGE_OPTIONAL_HEADER
ends


struct IMAGE_SECTION_HEADER
  Name			rb 8
  union
    PhysicalAddress	dd ?
    VirtualSize 	dd ?
  ends
  VirtualAddress	dd ?
  SizeOfRawData 	dd ?
  PointerToRawData	dd ?
  PointerToRelocations	dd ?
  PointerToLinenumbers	dd ?
  NumberOfRelocations	dw ?
  NumberOfLinenumbers	dw ?
  Characteristics	dd ?
ends


struct IMAGE_IMPORT_DESCRIPTOR
   union
     Characteristics	dd ?
     OriginalFirstThunk dd ?
   ends
   TimeDateStamp	dd ?
   ForwarderChain	dd ?
   Name 		dd ?
   FirstThunk		dd ?
ends

struct IMAGE_THUNK_DATA
   union
     ForwarderString	dd ?
     Function		dd ?
     Ordinal		dd ?
     AddressOfData	dd ?
   ends
ends

struct IMAGE_IMPORT_BY_NAME
   Hint 		dw ?
   Name 		db ?
ends

struct IMAGE_BASE_RELOCATION
   VirtualAddress	dd ?
   SizeOfBlock		dd ?
ends

struct IMAGE_EXPORT_DIRECTORY
   Characteristics	 dd ?
   TimeDateStamp	 dd ?
   MajorVersion 	 dw ?
   MinorVersion 	 dw ?
   Name 		 dd ?
   Base 		 dd ?
   NumberOfFunctions	 dd ?
   NumberOfNames	 dd ?
   AddressOfFunctions	 dd ?
   AddressOfNames	 dd ?
   AddressOfNameOrdinals dd ?
ends



