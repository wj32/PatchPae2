#include <ph.h>
#include <imagehlp.h>

#define ARG_OUTPUT 1
#define ARG_TYPE 2

#define TYPE_KERNEL 1
#define TYPE_LOADER 2

typedef VOID (NTAPI *PPATCH_FUNCTION)(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    );

PPH_STRING ArgInput;
PPH_STRING ArgOutput;
PPH_STRING ArgType;

ULONG ArgTypeInteger;

VOID Fail(
    __in PWSTR Message,
    __in ULONG Win32Result
    )
{
    if (Win32Result == 0)
        wprintf(L"%s\n", Message);
    else
        wprintf(L"%s: %s\n", Message, PhGetWin32Message(Win32Result)->Buffer);

    RtlExitUserProcess(STATUS_UNSUCCESSFUL);
}

ULONG GetBuildNumber(
    __in PWSTR FileName
    )
{
    ULONG buildNumber = 0;
    PVOID versionInfo;
    VS_FIXEDFILEINFO *rootBlock;
    ULONG rootBlockLength;

    versionInfo = PhGetFileVersionInfo(FileName);

    if (!versionInfo)
        return 0;

    if (VerQueryValue(versionInfo, L"\\", &rootBlock, &rootBlockLength) && rootBlockLength != 0)
        buildNumber = rootBlock->dwFileVersionLS >> 16;

    PhFree(versionInfo);

    return buildNumber;
}

ULONG GetRevisionNumber(
    __in PWSTR FileName
    )
{
    ULONG revisionNumber = 0;
    PVOID versionInfo;
    VS_FIXEDFILEINFO *rootBlock;
    ULONG rootBlockLength;

    versionInfo = PhGetFileVersionInfo(FileName);

    if (!versionInfo)
        return 0;

    if (VerQueryValue(versionInfo, L"\\", &rootBlock, &rootBlockLength) && rootBlockLength != 0)
        revisionNumber = rootBlock->dwFileVersionLS & 0xffff;

    PhFree(versionInfo);

    return revisionNumber;
}

VOID Patch(
    __in PPH_STRING FileName,
    __in PPATCH_FUNCTION Action
    )
{
    BOOLEAN success;
    PPH_BYTES mbFileName;
    LOADED_IMAGE loadedImage;

    mbFileName = PhConvertUtf16ToMultiByteEx(FileName->Buffer, FileName->Length);

    if (!MapAndLoad(mbFileName->Buffer, NULL, &loadedImage, FALSE, FALSE))
        Fail(L"Unable to map and load image", GetLastError());

    success = FALSE;
    Action(&loadedImage, &success);
    // This will unload the image and fix the checksum.
    UnMapAndLoad(&loadedImage);

    PhDereferenceObject(mbFileName);

    if (success)
        wprintf(L"Patched.\n");
    else
        Fail(L"Failed.", 0);
}

VOID PatchKernel(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // MxMemoryLicense

    // Basically, the portion of code we are going to patch 
    // queries the NT license value for the allowed memory.
    // If there is a limit, it sets MiTotalPagesAllowed to 
    // that limit times 256. If there is no specified limit, 
    // it sets MiTotalPagesAllowed to 0x80000 (2 GB).
    //
    // We will patch the limit to be 0x20000 << 8 pages (128 GB).

    UCHAR target[] =
    {
        // test eax, eax ; did ZwQueryLicenseValue succeed?
        0x85, 0xc0,
        // jl short loc_75644b ; if it didn't go to the default case
        0x7c, 0x11,
        // mov eax, [ebp+var_4] ; get the returned memory limit
        0x8b, 0x45, 0xfc,
        // test eax, eax ; is it non-zero?
        0x85, 0xc0,
        // jz short loc_75644b ; if it's zero, go to the default case
        0x74, 0x0a,
        // shl eax, 8 ; multiply by 256
        0xc1, 0xe0, 0x08
        // mov ds:_MiTotalPagesAllowed, eax ; store in MiTotalPagesAllowed
        // 0xa3, 0x2c, 0x76, 0x53, 0x00
        // jmp short loc_756455 ; go to the next bit
        // 0xeb, 0x0a
        // loc_75644b: mov ds:_MiTotalPagesAllowed, 0x80000
        // 0xc7, 0x05, 0x2c, 0x76, 0x53, 0x00, 0x00, 0x00, 0x08, 0x00
    };
    ULONG movOffset = 4;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov eax, [ebp+var_4] -> mov eax, 0x20000
            ptr[movOffset] = 0xb8;
            *(PULONG)&ptr[movOffset + 1] = 0x20000;
            // nop out the jz
            ptr[movOffset + 5] = 0x90;
            ptr[movOffset + 6] = 0x90;

            // Do the same thing to the next mov eax, [ebp+var_4] 
            // occurence.
            for (k = 0; k < 100; k++)
            {
                if (
                    ptr[k] == 0x8b &&
                    ptr[k + 1] == 0x45 &&
                    ptr[k + 2] == 0xfc &&
                    ptr[k + 3] == 0x85 &&
                    ptr[k + 4] == 0xc0
                    )
                {
                    // mov eax, [ebp+var_4] -> mov eax, 0x20000
                    ptr[k] = 0xb8;
                    *(PULONG)&ptr[k + 1] = 0x20000;
                    // nop out the jz
                    ptr[k + 5] = 0x90;
                    ptr[k + 6] = 0x90;

                    *Success = TRUE;

                    break;
                }
            }

            break;
        }

        ptr++;
    }
}

VOID PatchKernel9200(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // MxMemoryLicense

    // Basically, the portion of code we are going to patch 
    // queries the NT license value for the allowed memory.
    // If there is a limit, it sets MiTotalPagesAllowed to 
    // that limit times 256. If there is no specified limit, 
    // it sets MiTotalPagesAllowed to 0x80000 (2 GB).
    //
    // We will patch the limit to be 0x20000 << 8 pages (128 GB).

    UCHAR target[] =
    {
        // test eax, eax ; did NtQueryLicenseValue succeed?
        0x85, 0xc0,
        // js short loc_914314 ; if it didn't go to the default case
        0x78, 0x4c,
        // mov eax, [ebp+var_4] ; get the returned memory limit
        0x8b, 0x45, 0xfc,
        // test eax, eax ; is it non-zero?
        0x85, 0xc0,
        // jz short loc_914314 ; if it's zero, go to the default case
        0x74, 0x45,
        // shl eax, 8 ; multiply by 256
        0xc1, 0xe0, 0x08
        // mov ds:_MiTotalPagesAllowed, eax ; store in MiTotalPagesAllowed
        // ...
    };
    ULONG movOffset = 4;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 3 && j != 10) // ignore jump offsets
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov eax, [ebp+var_4] -> mov eax, 0x20000
            ptr[movOffset] = 0xb8;
            *(PULONG)&ptr[movOffset + 1] = 0x20000;
            // nop out the jz
            ptr[movOffset + 5] = 0x90;
            ptr[movOffset + 6] = 0x90;

            // Do the same thing to the next mov eax, [ebp+var_4] 
            // occurence.
            for (k = 0; k < 100; k++)
            {
                if (
                    ptr[k] == 0x8b &&
                    ptr[k + 1] == 0x45 &&
                    ptr[k + 2] == 0xfc &&
                    ptr[k + 3] == 0x85 &&
                    ptr[k + 4] == 0xc0
                    )
                {
                    // mov eax, [ebp+var_4] -> mov eax, 0x20000
                    ptr[k] = 0xb8;
                    *(PULONG)&ptr[k + 1] = 0x20000;
                    // nop out the jz
                    ptr[k + 5] = 0x90;
                    ptr[k + 6] = 0x90;

                    *Success = TRUE;

                    break;
                }
            }

            break;
        }

        ptr++;
    }
}

VOID PatchKernel9600(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // MxMemoryLicense

    // Basically, the portion of code we are going to patch 
    // queries the NT license value for the allowed memory.
    // If there is a limit, it sets MiTotalPagesAllowed to 
    // that limit times 256. If there is no specified limit, 
    // it sets MiTotalPagesAllowed to 0x80000 (2 GB).
    //
    // We will patch the limit to be 0x20000 << 8 pages (128 GB).

    UCHAR target[] =
    {
        // test eax, eax ; did NtQueryLicenseValue succeed?
        0x85, 0xc0,
        // js short loc_923593 ; if it didn't go to the default case
        0x78, 0x50,
        // mov eax, [ebp+var_4] ; get the returned memory limit
        0x8b, 0x45, 0xfc,
        // test eax, eax ; is it non-zero?
        0x85, 0xc0,
        // jz short loc_923593 ; if it's zero, go to the default case
        0x74, 0x49,
        // shl eax, 8 ; multiply by 256
        0xc1, 0xe0, 0x08
        // mov ds:_MiTotalPagesAllowed, eax ; store in MiTotalPagesAllowed
        // ...
    };
    ULONG movOffset = 4;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 3 && j != 10) // ignore jump offsets
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov eax, [ebp+var_4] -> mov eax, 0x20000
            ptr[movOffset] = 0xb8;
            *(PULONG)&ptr[movOffset + 1] = 0x20000;
            // nop out the jz
            ptr[movOffset + 5] = 0x90;
            ptr[movOffset + 6] = 0x90;

            // Do the same thing to the next mov eax, [ebp+var_4] 
            // occurence.
            for (k = 0; k < 100; k++)
            {
                if (
                    ptr[k] == 0x8b &&
                    ptr[k + 1] == 0x45 &&
                    ptr[k + 2] == 0xfc &&
                    ptr[k + 3] == 0x85 &&
                    ptr[k + 4] == 0xc0
                    )
                {
                    // mov eax, [ebp+var_4] -> mov eax, 0x20000
                    ptr[k] = 0xb8;
                    *(PULONG)&ptr[k + 1] = 0x20000;
                    // nop out the jz
                    ptr[k + 5] = 0x90;
                    ptr[k + 6] = 0x90;

                    *Success = TRUE;

                    break;
                }
            }

            break;
        }

        ptr++;
    }
}

VOID PatchKernel10586(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // MxMemoryLicense

    // Basically, the portion of code we are going to patch 
    // queries the NT license value for the allowed memory.
    // If there is a limit, it sets MiTotalPagesAllowed to 
    // that limit times 256. If there is no specified limit, 
    // it sets MiTotalPagesAllowed to 0x80000 (2 GB).
    //
    // We will patch the limit to be 0x20000 << 8 pages (128 GB).

    UCHAR target[] =
    {
        // test eax, eax ; did NtQueryLicenseValue succeed?
        0x85, 0xc0,
        // js short loc_96184f ; if it didn't go to the default case
        0x78, 0x46,
        // mov esi, [ebp+Address] ; get the returned memory limit
        0x8b, 0x75, 0xfc,
        // test esi, esi ; is it non-zero?
        0x85, 0xf6,
        // jz short loc_96184f ; if it's zero, go to the default case
        0x74, 0x3f,
        // shl esi, 8 ; multiply by 256
        0xc1, 0xe6, 0x08
        // ...
    };
    ULONG movOffset = 4;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 3 && j != 10) // ignore jump offsets
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov esi, [ebp+Address] -> mov esi, 0x20000
            ptr[movOffset] = 0xbe;
            *(PULONG)&ptr[movOffset + 1] = 0x20000;
            // nop out the jz
            ptr[movOffset + 5] = 0x90;
            ptr[movOffset + 6] = 0x90;

            // Do the same thing to the next mov ecx, [ebp+Address] 
            // occurence.
            for (k = 0; k < 100; k++)
            {
                if (
                    ptr[k] == 0x8b &&
                    ptr[k + 1] == 0x4d &&
                    ptr[k + 2] == 0xfc &&
                    ptr[k + 3] == 0x85 &&
                    ptr[k + 4] == 0xc9
                    )
                {
                    // mov ecx, [ebp+Address] -> mov ecx, 0x20000
                    ptr[k] = 0xb9;
                    *(PULONG)&ptr[k + 1] = 0x20000;
                    // nop out the jz
                    ptr[k + 5] = 0x90;
                    ptr[k + 6] = 0x90;

                    *Success = TRUE;

                    break;
                }
            }

            break;
        }

        ptr++;
    }
}

VOID PatchLoader(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadPEImageEx

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch BlImgLoadPEImageEx so that it doesn't care 
    // what the result of the function is.

    UCHAR target[] =
    {
        // sub esi, [ebx+4]
        0x2b, 0x73, 0x04,
        // push eax
        0x50,
        // add esi, [ebp+var_18]
        0x03, 0x75, 0xe8,
        // lea eax, [ebp+Source1]
        0x8d, 0x45, 0x8c,
        // push eax
        0x50,
        // push esi
        0x56,
        // mov eax, ebx
        0x8b, 0xc3
        // call _ImgpValidateImageHash@16
        // 0xe8, 0x59, 0x0b, 0x00, 0x00
        // mov ecx, eax ; copy return status into ecx
        // test ecx, ecx ; did ImgpValidateImageHash succeed?
        // mov [ebp+arg_0], ecx ; store the NT status into a variable
        // jge short loc_42109f ; if the function succeeded, go there
    };
    ULONG movOffset = 19;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov ecx, eax -> mov [ebp+arg_0], 0
            // 0x8b, 0xc8 -> 0xc7, 0x45, 0x08, 0x00, 0x00, 0x00, 0x00
            ptr[movOffset] = 0xc7;
            ptr[movOffset + 1] = 0x45;
            ptr[movOffset + 2] = 0x08;
            ptr[movOffset + 3] = 0x00;
            ptr[movOffset + 4] = 0x00;
            ptr[movOffset + 5] = 0x00;
            ptr[movOffset + 6] = 0x00;
            // jge short loc_42109f -> jmp short loc_42109f
            // 0x85, 0xc9 -> 0xeb, 0xc9
            ptr[movOffset + 7] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader7600(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadPEImage

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch BlImgLoadPEImage so that it doesn't care 
    // what the result of the function is.

    UCHAR target[] =
    {
        // push eax
        0x50,
        // lea eax, [ebp+Source1]
        0x8d, 0x85, 0x94, 0xfe, 0xff, 0xff,
        // push eax
        0x50,
        // push [ebp+var_12c]
        0xff, 0xb5, 0xd4, 0xfe, 0xff, 0xff,
        // mov eax, [ebp+var_24]
        0x8b, 0x45, 0xdc,
        // push [ebp+var_18]
        0xff, 0x75, 0xe8,
        // call _ImgpValidateImageHash@24
        // 0xe8, 0x63, 0x05, 0x00, 0x00
        // mov [ebp+var_8], eax ; copy return status into var_8
        // 0x89, 0x45, 0xf8
        // test eax, eax ; did ImgpValidateImageHash succeed?
        // 0x85, 0xc0
        // jge short loc_428ee5 ; if the function succeeded, go there
        // 0x7d, 0x2e
    };
    ULONG jgeOffset = 30;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that we don't need to update var_8 as it is 
            // a temporary status variable which will be overwritten 
            // very shortly.

            // jge short loc_428ee5 -> jmp short loc_428ee5
            // 0x7d, 0x2e -> 0xeb, 0x2e
            ptr[jgeOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader7601(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch ImgpLoadPEImage so that it doesn't care 
    // what the result of the function is.

    UCHAR target[] =
    {
        // push eax
        0x50,
        // lea eax, [ebp+Source1]
        0x8d, 0x85, 0x94, 0xfe, 0xff, 0xff,
        // push eax
        0x50,
        // push [ebp+var_12c]
        0xff, 0xb5, 0xd4, 0xfe, 0xff, 0xff,
        // mov eax, [ebp+var_24]
        0x8b, 0x45, 0xdc,
        // push [ebp+var_18]
        0xff, 0x75, 0xe8,
        // call _ImgpValidateImageHash@24
        // 0xe8, 0x63, 0x05, 0x00, 0x00
        // mov [ebp+var_8], eax ; copy return status into var_8
        // 0x89, 0x45, 0xf8
        // test eax, eax ; did ImgpValidateImageHash succeed?
        // 0x85, 0xc0
        // jge short loc_428f57 ; if the function succeeded, go there
        // 0x7d, 0x2e
    };
    ULONG jgeOffset = 30;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that we don't need to update var_8 as it is 
            // a temporary status variable which will be overwritten 
            // very shortly.

            // jge short loc_428f57 -> jmp short loc_428f57
            // 0x7d, 0x2e -> 0xeb, 0x2e
            ptr[jgeOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader7601_23569(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
)
{
  // ImgpValidateImageHash - patch to always return 0
/*
  .text:004295F7 
  .text:004295FF
  .text:004295FF                         loc_4295FF : ; CODE XREF : ImgpValidateImageHash(x, x, x, x, x) + 1Dj
  .text:004295FF; ImgpValidateImageHash(x, x, x, x, x) + A6j ...
  .text:004295FF 
*/
  UCHAR target[] =
  {
    // mov[esp + 70h + var_58], 0C0000428h; critical service failed
    0xC7, 0x44, 0x24, 0x18, 0x28, 0x04, 0x00, 0xC0,
    // 8B 44 24 18                             mov     eax, [esp + 70h + var_58]
    0x8B, 0x44, 0x24, 0x18,
  };
  ULONG jgeOffset = 8;
  PUCHAR ptr = LoadedImage->MappedAddress;
  ULONG i, j;

  *Success = FALSE;

  for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
  {
    for (j = 0; j < sizeof(target); j++)
    {
      if (ptr[j] != target[j])
        break;
    }

    if (j == sizeof(target))
    {
      // Found it. Patch the code.
      // Note that we don't need to update var_8 as it is 
      // a temporary status variable which will be overwritten 
      // very shortly.

      // mov eax, [esp + 70h + var_58] -> xor eax, eax; nop; nop
      // 0x7d, 0x2e -> 0xeb, 0x2e
      memcpy(ptr + jgeOffset, "\x31\xC0\x90\x90", 4);

      *Success = TRUE;

      break;
    }

    ptr++;
  }
}

// Version from https://github.com/Elbandi/PatchPae2, doesn't work for me
VOID PatchLoader7601_23569_0(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch ImgpLoadPEImage so that it doesn't care 
    // what the result of the function is.

    UCHAR target[] =
    {
        // lea eax, [ebp+Source1]
        0x8d, 0x85, 0x84, 0xfe, 0xff, 0xff,
        // push eax
        0x50,
        // push [ebp+var_28]
        0xff, 0x75, 0xd8,
        // mov eax, [ebp+arg_0]
        0x8b, 0x45, 0x08,
        // push dword ptr [eax+0Ch]
        0xff, 0x70, 0x0c,
        // lea eax, [ebp+var_64]
        0x8d, 0x45, 0x9c,
        // call _ImgpValidateImageHash@24
        // 0xe8, 0x5f, 0x05, 0x00, 0x00
        // mov [ebp+var_8], eax ; copy return status into var_8
        // 0x89, 0x45, 0xf8
        // test eax, eax ; did ImgpValidateImageHash succeed?
        // 0x85, 0xc0
        // jge short loc_428eae ; if the function succeeded, go there
        // 0x7d, 0x2e
    };
    ULONG jgeOffset = 29;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that we don't need to update var_8 as it is 
            // a temporary status variable which will be overwritten 
            // very shortly.

            // jge short loc_428eae -> jmp short loc_428eae
            // 0x7d, 0x2e -> 0xeb, 0x2e
            ptr[jgeOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader9200Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage

    UCHAR target[] =
    {
        // push eax
        0x50,
        // push [ebp+var_14]
        0xff, 0x75, 0xec,
        // lea eax, [ebp+var_13c]
        0x8d, 0x85, 0xc4, 0xfe, 0xff, 0xff,
        // push eax
        0x50,
        // push ecx
        0x51,
        // push dword ptr [esi+0ch]
        0xff, 0x76, 0x0c,
        // lea eax, [ebp+var_74]
        0x8d, 0x45, 0x8c,
        // call _ImgpValidateImageHash@24
        // 0xe8, 0x4f, 0x06, 0x00, 0x00
        // mov ebx, eax
        // 0x8b, 0xd8
        // test ebx, ebx ; did ImgpValidateImageHash succeed?
        // 0x85, 0xdb
        // jns short loc_43411d ; if the function succeeded, go there
        // 0x79, 0x2c
    };
    ULONG jnsOffset = 27;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that eax and ebx are not used later, so we can ignore them.

            // jns short loc_43411d -> jmp short loc_43411d
            // 0x79, 0x2c -> 0xeb, 0x2c
            ptr[jnsOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader9200Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadImageWithProgressEx

    UCHAR target[] =
    {
        // push 0
        0x6a, 0x00,
        // push [ebp+var_18]
        0xff, 0x75, 0xe8,
        // lea eax, [ebp+var_78]
        0x8d, 0x45, 0x88,
        // push eax
        0x50,
        // push [ebp+var_150]
        0xff, 0xb5, 0xb0, 0xfe, 0xff, 0xff,
        // xor eax, eax
        0x33, 0xc0,
        // push [ebp+arg_8]
        0xff, 0x75, 0x10
        // call _ImgpValidateImageHash@24
        // 0xe8, 0xe6, 0x13, 0x00, 0x00
        // mov ebx, eax
        // 0x8b, 0xd8
        // test ebx, ebx ; did ImgpValidateImageHash succeed?
        // 0x85, 0xdb
        // jns short loc_433374 ; if the function succeeded, go there
        // 0x79, 0x1a
    };
    ULONG movOffset = 25;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov ebx, eax -> xor ebx, ebx
            // 0x8b, 0xd8 -> 0x33, 0xdb
            ptr[movOffset] = 0x33;
            ptr[movOffset + 1] = 0xdb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader9200(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage and BlImgLoadImageWithProgressEx

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch ImgpLoadPEImage and BlImgLoadImageWithProgressEx
    // so that they don't care what the result of the function is.

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchLoader9200Part1(LoadedImage, &success1);
    PatchLoader9200Part2(LoadedImage, &success2);
    *Success = success1 && success2;
}

VOID PatchLoader9600Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage

    UCHAR target[] =
    {
        // push eax
        0x50,
        // push [ebp+var_78]
        0xff, 0x75, 0x88,
        // lea eax, [ebp+var_148]
        0x8d, 0x85, 0xb8, 0xfe, 0xff, 0xff,
        // push [ebp+var_14]
        0xff, 0x75, 0xec,
        // push eax
        0x50,
        // mov eax, [ebp+var_30]
        0x8b, 0x45, 0xd0,
        // push ecx
        0x51,
        // mov ecx, [eax+0ch]
        0x8b, 0x48, 0x0c,
        // call _ImgpValidateImageHash@32
        // 0xe8, 0x3a, 0x08, 0x00, 0x00
        // mov ebx, eax
        // 0x8b, 0xd8
        // test ebx, ebx ; did ImgpValidateImageHash succeed?
        // 0x85, 0xdb
        // jns short loc_434bc2 ; if the function succeeded, go there
        // 0x79, 0x2d
    };
    ULONG jnsOffset = 30;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that eax and ebx are not used later, so we can ignore them.

            // jns short loc_434bc2 -> jmp short loc_434bc2
            // 0x79, 0x2d -> 0xeb, 0x2d
            ptr[jnsOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader9600Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadImageWithProgress2

    UCHAR target[] =
    {
        // push 0
        0x6a, 0x00,
        // push 0
        0x6a, 0x00,
        // push [ebp+var_30]
        0xff, 0x75, 0xd0,
        // xor edx, edx
        0x33, 0xd2,
        // push [ebp+var_20]
        0xff, 0x75, 0xe0,
        // push eax
        0x50,
        // push [ebp+var_164]
        0xff, 0xb5, 0x9c, 0xfe, 0xff, 0xff,
        // call _ImgpValidateImageHash@32
        // 0xe8, 0x35, 0x17, 0x00, 0x00
        // mov esi, eax
        // 0x8b, 0xf0
        // test esi, esi ; did ImgpValidateImageHash succeed?
        // 0x85, 0xf6
        // jns short loc_433cec ; if the function succeeded, go there
        // 0x79, 0x52
    };
    ULONG movOffset = 24;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov esi, eax -> xor esi, esi
            // 0x8b, 0xf0 -> 0x33, 0xf6
            ptr[movOffset] = 0x33;
            ptr[movOffset + 1] = 0xf6;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader9600(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage and BlImgLoadImageWithProgressEx

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch ImgpLoadPEImage and BlImgLoadImageWithProgressEx
    // so that they don't care what the result of the function is.

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchLoader9600Part1(LoadedImage, &success1);
    PatchLoader9600Part2(LoadedImage, &success2);
    *Success = success1 && success2;
}

VOID PatchLoader10586Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage

    UCHAR target[] =
    {
        // lea eax, [ebp+var_180]
        0x8d, 0x85, 0x80, 0xfe, 0xff, 0xff,
        // push [ebp+var_10]
        0xff, 0x75, 0xf0,
        // push eax
        0x50,
        // push ecx
        0x51,
        // lea eax, [ebp+var_bc]
        0x8d, 0x85, 0x44, 0xff, 0xff, 0xff,
        // push eax
        0x50,
        // mov eax, [ebp+var_30]
        0x8b, 0x45, 0xd0,
        // push esi
        0x56,
        // mov ecx, [eax+0ch]
        0x8b, 0x48, 0x0c,
        // call _ImgpValidateImageHash@44
        // 0xe8, 0x7a, 0x0d, 0x00, 0x00
        // mov ebx, eax
        // 0x8b, 0xd8
        // test ebx, ebx ; did ImgpValidateImageHash succeed?
        // 0x85, 0xdb
        // js short loc_438a9d ; if the function did not succeed, go there
        // 0x0f, 0x88, 0x9f, 0x00, 0x00, 0x00
    };

	BOOL wildcardOffsets[sizeof(target)] = { 0 };
	wildcardOffsets[2] = TRUE;
	wildcardOffsets[13] = TRUE;
	wildcardOffsets[20] = TRUE;

    ULONG jnsOffset = 34;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if ((ptr[j] != target[j]) && !wildcardOffsets[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that eax and ebx are not used later, so we can ignore them.

            // js short loc_438a9d -> nop; nop; nop; nop; nop; nop
            // 0x0f, 0x88, 0x9f, 0x00, 0x00, 0x00 -> 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
            ptr[jnsOffset] = 0x90;
            ptr[jnsOffset + 1] = 0x90;
            ptr[jnsOffset + 2] = 0x90;
            ptr[jnsOffset + 3] = 0x90;
            ptr[jnsOffset + 4] = 0x90;
            ptr[jnsOffset + 5] = 0x90;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader10586Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadImageWithProgress2

    UCHAR target[] =
    {
        // push ecx
        0x51,
        // push ecx
        0x51,
        // push ecx
        0x51,
        // push [ebp+var_34]
        0xff, 0x75, 0xcc,
        // push [ebp+var_28]
        0xff, 0x75, 0xd8,
        // push eax
        0x50,
        // push [ebp+var_16c]
        0xff, 0xb5, 0x94, 0xfe, 0xff, 0xff,
        // push ecx
        0x51,
        // push [ebp+var_c]
        0xff, 0x75, 0xf4,
        // mov ecx, [ebp+arg_0]
        0x8b, 0x4d, 0x08,
        // call _ImgpValidateImageHash@44
        // 0xe8, 0x5c, 0x1e, 0x00, 0x00
        // mov esi, eax
        // 0x8b, 0xf0
        // test esi, esi ; did ImgpValidateImageHash succeed?
        // 0x85, 0xf6
        // jns short loc_43796a ; if the function succeeded, go there
        // 0x79, 0x52
    };
    ULONG wildcardOffset = 8;
    ULONG movOffset = 28;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if ((ptr[j] != target[j]) && j != wildcardOffset)
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov esi, eax -> xor esi, esi
            // 0x8b, 0xf0 -> 0x33, 0xf6
            ptr[movOffset] = 0x33;
            ptr[movOffset + 1] = 0xf6;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader10586(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage and BlImgLoadImageWithProgressEx

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch ImgpLoadPEImage and BlImgLoadImageWithProgressEx
    // so that they don't care what the result of the function is.

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchLoader10586Part1(LoadedImage, &success1);
    PatchLoader10586Part2(LoadedImage, &success2);
    *Success = success1 && success2;
}

BOOLEAN CommandLineCallback(
    __in_opt PPH_COMMAND_LINE_OPTION Option,
    __in_opt PPH_STRING Value,
    __in_opt PVOID Context
    )
{
    if (Option)
    {
        switch (Option->Id)
        {
        case ARG_OUTPUT:
            PhSwapReference(&ArgOutput, Value);
            break;
        case ARG_TYPE:
            PhSwapReference(&ArgType, Value);
            break;
        }
    }
    else
    {
        if (!ArgInput)
            PhSwapReference(&ArgInput, Value);
    }

    return TRUE;
}

int __cdecl main(int argc, char *argv[])
{
    static PH_COMMAND_LINE_OPTION options[] =
    {
        { ARG_OUTPUT, L"o", MandatoryArgumentType },
        { ARG_TYPE, L"type", MandatoryArgumentType }
    };

    PH_STRINGREF commandLine;
    ULONG buildNumber, revisionNumber;

    if (!NT_SUCCESS(PhInitializePhLibEx(0, 0, 0)))
        return 1;

    PhUnicodeStringToStringRef(&NtCurrentPeb()->ProcessParameters->CommandLine, &commandLine);
    PhParseCommandLine(&commandLine, options, sizeof(options) / sizeof(PH_COMMAND_LINE_OPTION), PH_COMMAND_LINE_IGNORE_FIRST_PART, CommandLineCallback, NULL);

    ArgTypeInteger = TYPE_KERNEL;

    if (ArgType)
    {
        if (PhEqualString2(ArgType, L"kernel", TRUE))
            ArgTypeInteger = TYPE_KERNEL;
        else if (PhEqualString2(ArgType, L"loader", TRUE))
            ArgTypeInteger = TYPE_LOADER;
        else
            Fail(L"Wrong type. Must be \"kernel\" or \"loader\".", 0);
    }

    if (PhIsNullOrEmptyString(ArgInput))
        Fail(L"Input file not specified!", 0);
    if (PhIsNullOrEmptyString(ArgOutput))
        Fail(L"Output file not specified!", 0);

    if (!CopyFile(ArgInput->Buffer, ArgOutput->Buffer, FALSE))
        Fail(L"Unable to copy file", GetLastError());

    if (!(buildNumber = GetBuildNumber(ArgOutput->Buffer)))
        Fail(L"Unable to get the build number of the file.", 0);

    if (!(revisionNumber = GetRevisionNumber(ArgOutput->Buffer)))
        Fail(L"Unable to get the revision number of the file.", 0);
	
	wprintf(L"Build %d, Revision %d\n", buildNumber, revisionNumber);

    if (ArgTypeInteger == TYPE_KERNEL)
    {
        if (buildNumber < 9200)
            Patch(ArgOutput, PatchKernel);
        else if (buildNumber == 9200)
            Patch(ArgOutput, PatchKernel9200);
        else if (buildNumber == 9600)
            Patch(ArgOutput, PatchKernel9600);
        else if (buildNumber == 10586)
            Patch(ArgOutput, PatchKernel10586);
        else
            Fail(PhFormatString(L"Unsupported kernel version: %u", buildNumber)->Buffer, 0);
    }
    else
    {
        if (buildNumber < 7600)
            Patch(ArgOutput, PatchLoader);
        else if (buildNumber == 7600)
            Patch(ArgOutput, PatchLoader7600);
        else if (buildNumber == 7601 && revisionNumber == 23569)
            Patch(ArgOutput, PatchLoader7601_23569);
        else if (buildNumber == 7601 && revisionNumber == 24517)
            Patch(ArgOutput, PatchLoader7601_23569_0);
        else if (buildNumber == 7601)
            Patch(ArgOutput, PatchLoader7601);
        else if (buildNumber == 9200)
            Patch(ArgOutput, PatchLoader9200);
        else if (buildNumber == 9600)
            Patch(ArgOutput, PatchLoader9600);
        else if (buildNumber >= 10240)
            Patch(ArgOutput, PatchLoader10586);
        else
            Fail(PhFormatString(L"Unsupported loader version: %u", buildNumber)->Buffer, 0);
    }

    return 0;
}
