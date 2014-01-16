#include "pipe.h"
#include "lookup.h"
#include "ignore.h"
#include "misc.h"

static IS_SUCCESS_NTSTATUS();

#define DUMP_FILE_MASK (GENERIC_WRITE | FILE_GENERIC_WRITE | \
    FILE_WRITE_DATA | FILE_APPEND_DATA | STANDARD_RIGHTS_WRITE | \
    STANDARD_RIGHTS_ALL)

#define HDDVOL1 L"\\Device\\HarddiskVolume1"

// length of a hardcoded unicode string
#define UNILEN(x) (sizeof(x) / sizeof(wchar_t) - 1)

typedef struct _file_record_t {
    unsigned int attributes;
    unsigned int length;
    wchar_t filename[0];
} file_record_t;

static lookup_t g_files;

void file_write(HANDLE file_handle);
void file_init();
void new_file(UNICODE_STRING *obj);
static void cache_file(HANDLE file_handle, const wchar_t *path,
    unsigned int length, unsigned int attributes);
void handle_new_file(HANDLE file_handle, OBJECT_ATTRIBUTES *obj);
void file_close(HANDLE file_handle);

