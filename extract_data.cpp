#include <Windows.h>
#include <stdio.h>

struct extra_data
{
	DWORD sig_1;
	DWORD sig_2;
	DWORD num_file;
	DWORD offset_1; /* look like size */
	DWORD offset_2;
	DWORD unknow_1;
	DWORD unknow_2;
	BYTE  name[0xD];
};

DWORD		get_end_file(void)
{
	HANDLE	hFile;
	HANDLE	hMap;
	IMAGE_DOS_HEADER *idh = NULL;
	IMAGE_NT_HEADERS *inh = NULL;
	IMAGE_SECTION_HEADER *ish = NULL;
	DWORD	size;
	BYTE	*map = NULL;
	DWORD	end_file = 0;

	hFile = CreateFileA("CoDSP.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
    {
		printf("CreateFileA() failed : %X\n", GetLastError());
		return (0);
    }
	size = GetFileSize(hFile, 0);
	hMap = CreateFileMappingA(hFile, 0, PAGE_READONLY, 0, size, 0);
	if (hMap == NULL)
	{
		printf("CreateFileMappingA() failed : %X\n", GetLastError());
		return (0);
	}
	map = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, size);
	if (map == NULL)
	{
		printf("MapViewOfFile() failed : %X\n", GetLastError());
		return (0);
	}
	idh = (IMAGE_DOS_HEADER *)map;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] IMAGE_DOS_SIGNATURE failed\n");
		return (0);
	}
	inh = (IMAGE_NT_HEADERS *)((BYTE*)map + idh->e_lfanew);
	if (inh->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[-] IMAGE_NT_SIGNATURE\n");
		return (0);
	}
	idh = (IMAGE_DOS_HEADER*)map;
	inh = (IMAGE_NT_HEADERS *)((BYTE*)map + idh->e_lfanew);
	ish = (IMAGE_SECTION_HEADER*)((BYTE*)inh + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * (inh->FileHeader.NumberOfSections - 1));
	end_file = ish->PointerToRawData + ish->SizeOfRawData;
	UnmapViewOfFile(map);
	CloseHandle(hMap);
	CloseHandle(hFile);
	return (end_file);
}

void print_data_info(struct extra_data *data)
{
	printf("Sig1 = %X\n", data->sig_1);
	printf("Sig2 = %X\n", data->sig_2);
	printf("Name : %s\n", data->name);
	printf("Num : %d\n", data->num_file);
}

int			get_extra_data(void)
{
	HANDLE	hFile;
	DWORD	fsize;
	DWORD	size_high;
	DWORD	actual_pos = 0x1AB000;
	BYTE	buff[0x121];
	DWORD	bread;
	DWORD	key;
	struct extra_data data;
	DWORD	i;

	if ((actual_pos = get_end_file()) == 0)
		return (0);

	hFile = CreateFileA("CoDSP.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
    {
      printf("[-] Echec lors de l'ouverture du fichier\n");
      return (0);
    }

	fsize = GetFileSize(hFile, &size_high);
	printf("File Size = %x\n", fsize);

	do
	{
		SetFilePointer(hFile, actual_pos, NULL, FILE_BEGIN);
		ReadFile(hFile, buff, 0x121, &bread, 0);
		key = actual_pos;

		for (i = 0; i < bread; i++)
		{
			key = key * 0x13C6A5;
			key += 0x0D8430DED;
			buff[i] ^= (((((key >> 0x10) ^ (key >> 0x8)) ^ (key >> 0x18)) ^ (key & 0xFF)) & 0xFF);
		}
		memcpy(&data, buff, sizeof(struct extra_data));
		print_data_info(&data);

		actual_pos += data.offset_1 + data.offset_2;

	} while (data.num_file != 0);
}