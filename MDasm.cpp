#include <stdio.h>
#include <inttypes.h>
#include <windows.h>
#include <capstone/capstone.h>
#include <inttypes.h>

#define CODE "\x00\x00\x00\x00\x00"

FILE _iob[] = { *stdin, *stdout, *stderr };

#pragma comment(lib, "legacy_stdio_definitions.lib")

extern "C" FILE * __cdecl __iob_func(void)
{
    return _iob;
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("Expected 3 arguments but got %d\n", argc);
        return 1;
    }

    const int offsetStart = atoi(argv[2]);
    const int offsetEnd = atoi(argv[3]);

    if (offsetEnd < offsetStart)
    {
        printf("Offset end must be after the start offset\n");
        return 1;
    }

    const int len = abs(offsetEnd - offsetStart);

    printf("Opening %s offset start = %d offset end = %d\n", argv[1], offsetStart, offsetEnd);
    FILE* file = fopen(argv[1], "rb");
    BYTE* pBuffer = new BYTE[len];
    if (!file)
    {
        printf("Failed to open %s\n", argv[1]);
        return 1;
    }

    if (fseek(file, offsetStart, SEEK_SET))
    {
        printf("seek failed\n");
        return 1;
    }

    const size_t readCount = fread(pBuffer, 1, len, file);
    if (readCount != len)
    {
        printf("Attempted to read %d bytes but got %d bytes\n", len, readCount);
        fclose(file);
        return 1;
    }

    fclose(file);


    csh handle;
    cs_insn *insn;

    if (cs_open(CS_ARCH_MIPS, CS_MODE_MIPS32, &handle) != CS_ERR_OK)
    {
        return -1;
    }

    const size_t count = cs_disasm(handle, (const uint8_t*)pBuffer, offsetEnd, 0x0, 0, &insn);

    if (count > 0)
    {
        for (size_t j = 0; j < count; j++)
        {
            printf("0x%llx:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble given code!\n");
    }

    cs_close(&handle);

    return 0;
}