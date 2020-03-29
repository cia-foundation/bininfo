#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef bool Bool;
typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef int64_t I64;

#define StrLen strlen

const static bool TRUE = true;
const static bool FALSE = false;

#define IET_END                 0
#define IET_REL_I0              2
#define IET_IMM_U0              3
#define IET_REL_I8              4
#define IET_IMM_U8              5
#define IET_REL_I16             6
#define IET_IMM_U16             7
#define IET_REL_I32             8
#define IET_IMM_U32             9
#define IET_REL_I64             10
#define IET_IMM_I64             11
#define IET_REL32_EXPORT        16
#define IET_IMM32_EXPORT        17
#define IET_REL64_EXPORT        18
#define IET_IMM64_EXPORT        19
#define IET_ABS_ADDR            20
#define IET_CODE_HEAP           21
#define IET_ZEROED_CODE_HEAP    22
#define IET_DATA_HEAP           23
#define IET_ZEROED_DATA_HEAP    24
#define IET_MAIN                25

static const char BIN_SIGNATURE[] = "TOSB";

typedef struct CBinFile {
  U8    jmp[2];
  U8    module_align_bits,
        reserved;
  U8    bin_signature[4];
  I64   org,
        patch_table_offset,
        file_size;
}  CBinFile;

/* adapted directly from https://github.com/cia-foundation/TempleOS/blob/archive/Kernel/KLoad.HC */

void LoadOneImport(U8 **_src,U8 *module_base,I64 ld_flags)
{
  U8 *src=*_src,*ptr2,*st_ptr;
  I64 i,etype;
  Bool first=TRUE;

  printf("    at");

  for (int counter = 0; etype=*src++; counter++) {
    uintptr_t i = 0;
    memcpy(&i, src, 4);
    src += 4;
    st_ptr=src;
    src+=StrLen(st_ptr)+1;

    if (*st_ptr) {
      if (!first) {
        *_src=st_ptr-5;
        printf("\n");
        return;
      } else {
        first=FALSE;
      }
    }

    if (counter !=0 && counter % 8 == 0) {
      printf("\n      ");
    }

    printf(" %8Xh", i);
  }
  *_src=src-1;

  printf("\n");
}

char const* etype_to_string(int64_t etype) {
  char const* etype_names[] = {
    "IET_END",
    NULL,
    "IET_REL_I0",
    "IET_IMM_U0",
    "IET_REL_I8",
    "IET_IMM_U8",
    "IET_REL_I16",
    "IET_IMM_U16",
    "IET_REL_I32",
    "IET_IMM_U32",
    "IET_REL_I64",
    "IET_IMM_I64",
    NULL,
    NULL,
    NULL,
    NULL,
    "IET_REL32_EXPORT",
    "IET_IMM32_EXPORT",
    "IET_REL64_EXPORT",
    "IET_IMM64_EXPORT",
    "IET_ABS_ADDR",
    "IET_CODE_HEAP",
    "IET_ZEROED_CODE_HEAP",
    "IET_DATA_HEAP",
    "IET_ZEROED_DATA_HEAP",
    "IET_MAIN",
  };

  if (etype >= 0 && etype < sizeof(etype_names) / sizeof(*etype_names) && etype_names[etype]) {
    return etype_names[etype];
  }
  else {
    static char buffer[20];
    snprintf(buffer, sizeof(buffer), "IET_#%lld", etype);
    return buffer;
  }
}

void LoadPass1(U8 *src,U8 *module_base,I64 ld_flags)
{
  U8 *ptr2,*ptr3,*st_ptr;
  I64 i,j,cnt,etype;

  printf("Patch table:\n");

  while (etype=*src++) {
    uint32_t i = 0;
    memcpy(&i, src, 4);
    src += 4;
    st_ptr=src;
    src+=StrLen(st_ptr)+1;
    printf("  entry %s \"%s\"\n", etype_to_string(etype), st_ptr);
    switch (etype) {
      case IET_REL32_EXPORT:
      case IET_IMM32_EXPORT:
      case IET_REL64_EXPORT:
      case IET_IMM64_EXPORT:
        printf("    export %-40s @ %8Xh\n", st_ptr, i);
        break;
      case IET_REL_I0:
      case IET_IMM_U0:
      case IET_REL_I8:
      case IET_IMM_U8:
      case IET_REL_I16:
      case IET_IMM_U16:
      case IET_REL_I32:
      case IET_IMM_U32:
      case IET_REL_I64:
      case IET_IMM_I64:
        src=st_ptr-5;
        LoadOneImport(&src,module_base,ld_flags);
        break;
      case IET_ABS_ADDR:
        printf("    at");
        cnt=i;
        for (j=0;j<cnt;j++) {
          uint32_t val = 0;
          memcpy(&val, src, 4);
          src += 4;

          if (j !=0 && j % 8 == 0) {
            printf("\n      ");
          }

          printf(" %8Xh", val);
        }
        printf("\n");
        break;

      case IET_MAIN:
        printf("    main function @ %8Xh\n", i);
        break;

      default:
        printf("    UNHANDLED\n");
    }
  }
}

int main(int argc, char* argv[]) {
  int rc = -1;

  if (argc != 2) {
    fprintf(stderr, "usage: bininfo <filename>\n");
    return -1;
  }

  char const* filename = argv[1];

  FILE* f = fopen(filename, "rb");

  if (!f) {
    fprintf(stderr, "bininfo: %s\n", strerror(errno));
    return -1;
  }

  CBinFile bfh;

  if (!fread(&bfh, sizeof(bfh), 1, f)) {
    fprintf(stderr, "bininfo error: not a BIN file (incomplete header)\n");
    goto exit1;
  }

  /* validate header */

  if (memcmp(bfh.bin_signature, BIN_SIGNATURE, sizeof(bfh.bin_signature)) != 0) {
    fprintf(stderr, "bininfo error: not a BIN file (signature %c%c%c%c)\n",
        bfh.bin_signature[0], bfh.bin_signature[1], bfh.bin_signature[2], bfh.bin_signature[3]);
    goto exit1;
  }

  I64 module_align = 1 << bfh.module_align_bits;
  if (!module_align) {
    fprintf(stderr, "bininfo error: not a BIN file (invalid alignment)\n");
    goto exit1;
  }

  printf("bininfo %s\n\n", filename);

  /* print header info */
  printf("BIN header:\n");
  printf("    jmp                 [%02X %02X]h\n", bfh.jmp[0], bfh.jmp[1]);
  printf("    alignment           %d byte(s)\n", module_align);
  printf("    org                 %016llX (%lld)\n", bfh.org, bfh.org);
  printf("    patch_table_offset  %016llX (%lld)\n", bfh.patch_table_offset, bfh.patch_table_offset);
  printf("    file_size           %016llX (%lld)\n", bfh.file_size, bfh.file_size);
  printf("\n");

  /* attempt to load rest of the file */
  uint8_t* binfile = (uint8_t*) malloc(bfh.file_size);

  fseek(f, 0, SEEK_SET);
  size_t r = fread(binfile, 1, bfh.file_size, f);

  if (r != bfh.file_size) {
    fprintf(stderr, "bininfo warning: invalid file_size (expected %lld, got %zu bytes)\n", bfh.file_size, r);
  }

  char dummy;

  /* feof will NOT return true until we attempt to read past the end of file */
  if (fread(&dummy, 1, 1, f)) {
    fprintf(stderr, "bininfo warning: invalid file_size (extra bytes at end of file)\n");
  }

  uint8_t* module_base = binfile + sizeof(struct CBinFile);
  LoadPass1(binfile + bfh.patch_table_offset, module_base, 0);
  rc = 0;

exit2:
  free(binfile);

exit1:
  fclose(f);

  return rc;
}
