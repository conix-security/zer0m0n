#include <windows.h>
#include "main.h"
#include "file.h"

void file_init()
{
    lookup_init(&g_files);
}

void new_file(UNICODE_STRING *obj)
{
	wchar_t *buf = malloc(wcslen(HDDVOL) * sizeof(wchar_t));
    wchar_t *str = obj->Buffer;
    unsigned int len = obj->Length / sizeof(wchar_t);

    // if it's a path including \??\ then we can send it straight away,
    // but we strip the \??\ part
    if(len > 4 && !wcsncmp(str, L"\\??\\", 4)) {
        pipe("FILE_NEW:%S", len - 4, str + 4);
    }
    // maybe it's an absolute path (or a relative path with a harddisk,
    // such as C:abc.txt)
    else if(isalpha(str[0]) != 0 && str[1] == ':') {
        pipe("FILE_NEW:%S", len, str);
    }
    // the filename starts with \Device\HarddiskVolume
	else if(wcsistr(str, HDDVOL)) {
		wcsncpy(buf, str, wcslen(HDDVOL));
		if(wcsicmp(buf, str))
		{
			str += UNILEN(HDDVOL)+1; 
			len -= UNILEN(HDDVOL);
			pipe("FILE_NEW:C:%S", len, str);
		}
	}

	free(buf);
}


static void cache_file(HANDLE file_handle, const wchar_t *path,
    unsigned int length, unsigned int attributes)
{
    file_record_t *r = lookup_add(&g_files, (unsigned int) file_handle,
        sizeof(file_record_t) + length * sizeof(wchar_t) + sizeof(wchar_t));

	r->attributes = attributes;
	r->length = length * sizeof(wchar_t);

    memcpy(r->filename, path, r->length);
    r->filename[r->length / sizeof(wchar_t)] = 0;
}

void file_write(HANDLE file_handle)
{
	UNICODE_STRING str;
    file_record_t *r = lookup_get(&g_files, (unsigned int) file_handle, NULL);
    if(r != NULL) {
		str.Length = r->length;
		str.MaximumLength = r->length + sizeof(wchar_t);
		str.Buffer = r->filename;
       
        // we do in fact want to dump this file because it was written to
        new_file(&str);

        // delete the file record from the list
        lookup_del(&g_files, (unsigned int) file_handle);
    }
}

void handle_new_file(HANDLE file_handle, OBJECT_ATTRIBUTES *obj)
{
    if(is_directory_objattr(obj) == 0 && is_ignored_file_objattr(obj) == 0) {

        wchar_t fname[MAX_PATH]; int length;
        length = path_from_object_attributes(obj, fname);

        length = ensure_absolute_path(fname, fname, length);

        // cache this file
        cache_file(file_handle, fname, length, obj->Attributes);
    }
}

void file_close(HANDLE file_handle)
{
    lookup_del(&g_files, (unsigned int) file_handle);
}

wchar_t *wcsistr(wchar_t *wcs1, wchar_t *wcs2)
{
    const wchar_t *s1, *s2;
    const wchar_t l = towlower(*wcs2);
    const wchar_t u = towupper(*wcs2);
    
    if (!*wcs2)
        return wcs1;
    
    for (; *wcs1; ++wcs1)
    {
        if (*wcs1 == l || *wcs1 == u)
        {
            s1 = wcs1 + 1;
            s2 = wcs2 + 1;
            
            while (*s1 && *s2 && towlower(*s1) == towlower(*s2))
                ++s1, ++s2;
            
            if (!*s2)
                return wcs1;
        }
    }
 
    return NULL;
} 