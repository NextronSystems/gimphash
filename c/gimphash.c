#include <yara/pe_utils.h>

#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

// read_file reads a file into a newly allocated buffer.
// it is the user's responsibility to free that buffer after use.
void read_file(char* filename, uint8_t** data, size_t *data_size) {
   FILE* fd = fopen(filename, "r");
   fseek(fd, 0, SEEK_END);
   *data_size = ftell(fd);
   fseek(fd, 0, SEEK_SET);
   *data = malloc(*data_size);
   fread(*data, *data_size, 1, fd);
   fclose(fd);
}

#define PCLNTAB_MAGIC_SIZE 6

// pclntabmagic is the magic bytes used for binaries compiled with Go
// prior to 1.16
uint8_t pclntabmagic[PCLNTAB_MAGIC_SIZE] = {0xfb, 0xff, 0xff, 0xff, 0x00, 0x00};

// pclntab116magic is the magic bytes used for binaries compiled with
// Go 1.16 and Go 1.17.
uint8_t pclntab116magic[PCLNTAB_MAGIC_SIZE] = {0xfa, 0xff, 0xff, 0xff, 0x00, 0x00};

// pclntab118magic is the magic bytes used for binaries compiled with
// Go 1.18 and onwards.
uint8_t pclntab118magic[PCLNTAB_MAGIC_SIZE] = {0xf0, 0xff, 0xff, 0xff, 0x00, 0x00};

#define PCLNTAB_MAGIC_COUNT 3

uint8_t* pclntab_magics[PCLNTAB_MAGIC_COUNT] = {pclntab118magic, pclntab116magic, pclntabmagic};

// find_pe_pclntab searches for the pclntab in the given binary.
// The pclntab will be returned in the last two parameters, which will be zero if the pclntab could not be found.
// The returned data will be part of the passed data block and thus does not have to be freed.
void find_pe_pclntab(uint8_t* data, size_t data_size, uint8_t** pclntab, size_t* pclntab_size) {
   *pclntab = 0;
   *pclntab_size = 0;

   PIMAGE_NT_HEADERS32 pe_header = pe_get_header(data, data_size);

   if (pe_header == NULL) {
      return;
   }

   PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pe_header);

   int scount = yr_min(yr_le16toh(pe_header->FileHeader.NumberOfSections), MAX_PE_SECTIONS);
   char section_name[IMAGE_SIZEOF_SHORT_NAME + 1];

   // Search for .text and .rdata section; one of them contains the pclntab
   for (int i = 0; i < scount; i++) {
      size_t size = sizeof(IMAGE_SECTION_HEADER);

      // sanity check: check whether section header boundaries are valid
      if (!((size_t)(size) <= data_size && (uint8_t*) (section) >= data && (uint8_t*) (section) <= data + data_size - (size))) {
         break;
      }

      if (i != 0) {
         section++;
      }

      memcpy(section_name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
      section_name[IMAGE_SIZEOF_SHORT_NAME] = '\0';

      if (strcmp(".text", section_name) != 0 && strcmp(".rdata", section_name) != 0) {
         continue;
      }
      // sanity check: check whether section data boundaries are valid
      if (section->PointerToRawData > data_size || section->SizeOfRawData > data_size || section->PointerToRawData + section->SizeOfRawData > data_size) {
         continue;

      }
      uint8_t* section_start = data + section->PointerToRawData;
      size_t section_size = section->SizeOfRawData;
      if (section_size <= PCLNTAB_MAGIC_SIZE) {
         continue;
      }
      // search for the known magic headers by iterating backwards through the section
      for (int i = 0; i < PCLNTAB_MAGIC_COUNT; i++) {
         uint8_t* magic = pclntab_magics[i];

         size_t index = section_size - PCLNTAB_MAGIC_SIZE;
         while (--index > 0) {
            uint8_t* potential_tab = section_start + index;
            if (memcmp(potential_tab, magic, PCLNTAB_MAGIC_SIZE) != 0) {
               continue;
            }
            // potential hit based on the header - verify the next bytes, based on https://github.com/golang/go/blob/db875f4d1b125e41a3999e3dd5c30d6b1bce235c/src/debug/gosym/pclntab.go#L210
            if (potential_tab[6] != 1 && potential_tab[6] != 2 && potential_tab[6] != 4) {
               continue;
            }
            if (potential_tab[7] != 4 && potential_tab[7] != 8) {
               continue;
            }
            // pclntab located, return it
            *pclntab = potential_tab;
            *pclntab_size = section_size - index;
            return;
         }
      }
   }
   return;
}

#define VER12 1
#define VER116 2
#define VER118 3

// pclntab_version is a small helper that returns the version based on the pclntab's magic header.
int pclntab_version(uint8_t* pcln_tab) {
   if (memcmp(pcln_tab, pclntabmagic, PCLNTAB_MAGIC_SIZE) == 0) {
      return VER12;
   }
   if (memcmp(pcln_tab, pclntab116magic, PCLNTAB_MAGIC_SIZE) == 0) {
      return VER116;
   }
   if (memcmp(pcln_tab, pclntab118magic, PCLNTAB_MAGIC_SIZE) == 0) {
      return VER118;
   }
   return 0;
}

// safe_array is a small, Golang slice inspired struct that contains a pointer and the amount of data that is valid after the pointer.
typedef struct {
   uint8_t* data;
   size_t data_size;
} safe_array;

// safe_array_offset increases a data pointer by a given offset. If this offset exceeds the limits, an empty safe_array is returned.
safe_array safe_array_offset(safe_array base, size_t offset) {
   safe_array offset_data;
   if (base.data_size > offset) {
      offset_data.data = base.data + offset;
      offset_data.data_size = base.data_size - offset;
   } else {
      offset_data.data = 0;
      offset_data.data_size = 0;
   }
   return offset_data;
}

// uintptr reads a ptr_sized value from the safe array.
uint64_t uintptr(safe_array data, uint32_t ptr_size) {
   if (ptr_size == 4) {
      if (data.data_size < 4) {
         return 0;
      }
      return *(uint32_t*)data.data;
   }
   if (data.data_size < 8) {
      return 0;
   }
   return *(uint64_t*)data.data;
}

// C equivalents of the two helper functions here: https://github.com/golang/go/blob/db875f4d1b125e41a3999e3dd5c30d6b1bce235c/src/debug/gosym/pclntab.go#L241
#define offset(word) uintptr(safe_array_offset(pcln_tab, 8+word * ptr_size), ptr_size)
#define data(word) safe_array_offset(pcln_tab, offset(word))

int functab_field_size(int version, int ptrsize) {
   if (version >= VER118) {
      return 4;
   }
   return ptrsize;
}

// C equivalent of https://github.com/golang/go/blob/db875f4d1b125e41a3999e3dd5c30d6b1bce235c/src/debug/gosym/pclntab.go#L461
uint32_t func_data_field(safe_array func_data, uint32_t n, uint32_t functab_field_size) {
   uint32_t sz0 = functab_field_size;
   uint32_t off = sz0 + (n - 1) * 4;
   safe_array offset_data = safe_array_offset(func_data, off);
   if (offset_data.data_size < 4) {
      return 0;
   }
   return *((uint32_t*) offset_data.data);
}

// Small helper that safely checks a string's length (basically strnlen)
size_t strlen_safe( const char *str, size_t strsz ) {
   if (str == 0) {
      return 0;
   }
   size_t strlength = 0;
   while (str[strlength] != 0 && strlength < strsz) {
      strlength++;
   }
   return strlength;
}

// parse_pcln_tab parses a given pclntab and returns a list of all packages that were found that are not excluded by gimphash criteria (see README.md in the top directory).
char** parse_pcln_tab(uint8_t* pcln_tab_data, size_t pcln_max_tab_size, size_t* name_count) {
   *name_count = 0;

   uint32_t ptr_size = pcln_tab_data[7];

   int version = pclntab_version(pcln_tab_data);

   safe_array pcln_tab;
   pcln_tab.data = pcln_tab_data;
   pcln_tab.data_size = pcln_max_tab_size;

   // Initialize function tab values, analogous to https://github.com/golang/go/blob/db875f4d1b125e41a3999e3dd5c30d6b1bce235c/src/debug/gosym/pclntab.go#L248
   uint32_t nfunctab;
   safe_array functab;
   safe_array funcdata;
   safe_array funcnametab;
   size_t functabsize;
   if (version == VER118) {
      nfunctab = offset(0);
      funcnametab = data(3);
      functab = data(7);
      funcdata = data(7);
   } else if (version == VER116) {
      nfunctab = offset(0);
      funcnametab = data(2);
      functab = data(6);
      funcdata = data(6);
   } else if (version == VER12) {
      nfunctab = uintptr(safe_array_offset(pcln_tab, 8), ptr_size);
      funcnametab = pcln_tab;
      functab = safe_array_offset(pcln_tab, 8+ptr_size);
      funcdata = pcln_tab;
   }
   int ftab_field_size = functab_field_size(version, ptr_size);
   functabsize = (nfunctab * 2 + 1) * ftab_field_size;

   if (functabsize > functab.data_size) {
      return 0;
   }
   
   // names_capacity contains the actual size of names. This avoids realloc() calls on every loop iteration.
   size_t names_capacity = 10;
   char** names = malloc(sizeof(char*) * names_capacity);
   if (names == 0) {
      return 0;
   }
   for (uint32_t i = 0; i < nfunctab; i++) {
      // Read name based on https://github.com/golang/go/blob/db875f4d1b125e41a3999e3dd5c30d6b1bce235c/src/debug/gosym/pclntab.go#L311
      uint64_t func_offset = uintptr(safe_array_offset(functab, (2*i+1)*ftab_field_size), ftab_field_size);
      safe_array func_data = safe_array_offset(funcdata, func_offset);
      if (func_data.data_size == 0) {
         free(names);
         return 0;
      }

      uint32_t name_offset = func_data_field(func_data, 1, ftab_field_size);
      safe_array name_array = safe_array_offset(funcnametab, name_offset);

      // Sanity check: resulting pointer should be a zero-terminated string
      char* name = (char*) name_array.data;
      size_t namelength = strlen_safe(name, name_array.data_size);
      if (namelength == name_array.data_size) {
         free(names);
         return 0;
      }

      // From here on, do the gimphash excludes as described in README.md
      if (strncmp(name, "go.", 3) == 0 || strncmp(name, "type.", 5) == 0) {
         continue;
      }
      if (strncmp(name, "internal/", 9) == 0 || strncmp(name, "vendor/", 7) == 0) {
         continue;
      }

      while (namelength > 0) {
         if (name[namelength] == '/') {
            break;
         }
         namelength--;
      }
      if (namelength == 0) {
         continue;
      }
      while (name[namelength] != '.' && name[namelength] != '\0') {
         namelength++;
      }

      if (name[namelength] == '\0') {
         continue;
      }

      size_t first_separator = 0;

      while (first_separator < namelength) {
         if (name[first_separator] == '/') {
            break;
         }
         first_separator++;
      }
      if (first_separator != 0) {
         bool has_dot = false;
         for (size_t i = 0; i < first_separator; i++) {
            if (name[i] == '.') {
               has_dot = true;
               break;
            }
         }
         if (has_dot) {
            if (strncmp(name, "golang.org/", first_separator+1) != 0 && strncmp(name, "github.com/", first_separator+1) != 0 && strncmp(name, "gitlab.com/", first_separator+1) != 0 && strncmp(name, "gopkg.in/", first_separator+1) != 0 && strncmp(name, "google.golang.org/", first_separator+1) != 0 && strncmp(name, "cloud.google.com/", first_separator+1) != 0) {
               continue;
            }
         }
      }

      // Package qualifies - allocate a new buffer to add to names
      char* nameBuffer = malloc(namelength + 1);
      if (nameBuffer == 0) {
         free(names);
         *name_count = 0;
         return 0;
      }
      memcpy(nameBuffer, name, namelength);
      nameBuffer[namelength] = '\0';

      // Check if package already exists
      bool nameExists = false;
      for (size_t i = 0; i < *name_count; i++) {
         if (strcmp(names[i], nameBuffer) == 0) {
            nameExists = true;
            break;
         }
      }
      if (nameExists) {
         free(nameBuffer);
         continue;
      }

      // realloc names, if required, and add new element
      if (names_capacity == *name_count) {
         names_capacity *= 2;
         names = realloc(names, sizeof(char*) * names_capacity);
      }
      names[*name_count] = nameBuffer;
      (*name_count)++;
   }

   return names;
}

int pstrcmp( const void* a, const void* b )
{
  return strcmp( *(const char**)a, *(const char**)b );
}

#define SHA256_LEN 32

int main(int argc, char** argv) {
   if (argc < 2) {
      printf("Usage: %s executable1 [executable2 ... ]\n", argv[0]);
      return 0;
   }

   for (int file_index = 1; file_index < argc; file_index++) {
      uint8_t* data = 0;
      size_t data_size = 0;
      // Read file
      read_file(argv[file_index], &data, &data_size);
      if (data == 0) {
         printf("Could not read file %s\n", argv[file_index]);
         continue;
      }

      // Check PE header. This happens in the next function anyway, but allows for more specific error messages
      PIMAGE_NT_HEADERS32 pe_header = pe_get_header(data, data_size);

      if (pe_header == NULL) {
         printf("Could not parse PE header in file %s\n", argv[file_index]);
         free(data);
         continue;
      }

      // Locate PCLN tab
      uint8_t* pclntab = 0;
      size_t pclntab_size = 0;
      find_pe_pclntab(data, data_size, &pclntab, &pclntab_size);

      if (pclntab == 0) {
         printf("Could not find pclntab in %s\n", argv[file_index]);
         free(data);
         continue;
      }
      
      // Parse PCLN tab
      size_t name_count = 0;
      char** names = parse_pcln_tab(pclntab, pclntab_size, &name_count);

      if (names == 0) {
         printf("Could not parse pclntab in %s\n", argv[file_index]);
         continue;
      }

      free(data);

      // Sort packages
      qsort( names, name_count, sizeof((char*)0), pstrcmp );

      // Calculate hash
      SHA256_CTX ctx;
      SHA256_Init(&ctx);

      for (size_t i = 0; i < name_count; i++) {
         //printf("Package: %s\n", names[i]);
         SHA256_Update(&ctx, names[i], strlen(names[i]));
         free(names[i]);
      }
      free(names);

      unsigned char digest[SHA256_LEN];
      SHA256_Final(digest, &ctx);

      char* digest_ascii = (char*) malloc(SHA256_LEN * 2 + 1);

      if (digest_ascii == 0) {
         return 1;
      }

      for (int i = 0; i < SHA256_LEN; i++)
      {
         sprintf(digest_ascii + (i * 2), "%02x", digest[i]);
      }
      digest_ascii[SHA256_LEN * 2] = '\0';
      printf("%s %s\n", digest_ascii, argv[file_index]);
      free(digest_ascii);
  }
 
   return 0;
}