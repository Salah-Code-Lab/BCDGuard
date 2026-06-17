// BCDGuard.c

/*
This Driver is meant to protect the BCD files but there is functionality loss
If you do Shift + Restart
you will boot to WinRE
BUT without any of the options the only option is to boot to UEFI mode
And you no longer can edit the BCD while booting normally
you have to boot to safe mode to do so
So Dual boot or writing new flags to the BCD will have a MINOR just a MINOR inconvenience because you must hard shut down
the OS twice
By loading this driver you accept the functionality loos
and all other False positives that may be triggered
Thanks for Viewing/loading BCDGuard
and Viewing/Loading Salah-Code-Lab Solutions
remember Stay safe !
*/

#include <fltKernel.h>
#include <ntdddisk.h>
#include <ntstrsafe.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_FILTER gFilterHandle = NULL;
BOOLEAN gProtectionActive = FALSE;

BOOLEAN g_MBRP = FALSE;
BOOLEAN g_EFIP = FALSE;
extern PULONG InitSafeBootMode;

// Standard GPT paths 
UNICODE_STRING gSystemBootBcdRel = RTL_CONSTANT_STRING(L"\\Windows\\Boot\\DVD\\EFI\\BCD");
UNICODE_STRING gSystem32BcdRel = RTL_CONSTANT_STRING(L"\\Windows\\System32\\Config\\BCD-Template");
UNICODE_STRING gEfiBcdRel = RTL_CONSTANT_STRING(L"\\EFI\\Microsoft\\Boot\\BCD");
UNICODE_STRING gMbrBcdRel = RTL_CONSTANT_STRING(L"\\Boot\\BCD");
UNICODE_STRING gMbrWinreBcdRel = RTL_CONSTANT_STRING(L"\\Windows\\Boot\\DVD\\PCAT\\BCD");



// Instance context
typedef struct _INSTANCE_CONTEXT {
    BOOLEAN IsFat32; 
    BOOLEAN IsNtfs;  
} INSTANCE_CONTEXT, * PINSTANCE_CONTEXT;



// Instance setup
NTSTATUS InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
) {
    UNREFERENCED_PARAMETER(Flags);

    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    PFLT_CONTEXT ctx;
    NTSTATUS status = FltAllocateContext(gFilterHandle, FLT_INSTANCE_CONTEXT,
        sizeof(INSTANCE_CONTEXT), NonPagedPoolNx, &ctx);

    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS; // Attach anyway, but without context
    }

    RtlZeroMemory(ctx, sizeof(INSTANCE_CONTEXT));
    PINSTANCE_CONTEXT instanceCtx = (PINSTANCE_CONTEXT)ctx;

    // ESP is formatted as FAT16/FAT32. OS drives are NTFS/ReFS. If you didn't know that now you know :D
    if (VolumeFilesystemType == FLT_FSTYPE_FAT) {
        instanceCtx->IsFat32 = TRUE;
    }
    else if (VolumeFilesystemType == FLT_FSTYPE_NTFS || VolumeFilesystemType == FLT_FSTYPE_REFS) {
        instanceCtx->IsNtfs = TRUE;
    }

    FltSetInstanceContext(FltObjects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx, NULL);
    FltReleaseContext(ctx);

    return STATUS_SUCCESS;
}

// Check if path matches protected paths via Relative matching
BOOLEAN IsProtectedPath(PFLT_FILE_NAME_INFORMATION NameInfo, PINSTANCE_CONTEXT Ctx) {

    if (NameInfo->Name.Length <= NameInfo->Volume.Length) {
        return FALSE;
    }

    UNICODE_STRING relativePath;
    relativePath.Buffer = (PWCH)((PUCHAR)NameInfo->Name.Buffer + NameInfo->Volume.Length);
    relativePath.Length = NameInfo->Name.Length - NameInfo->Volume.Length;
    relativePath.MaximumLength = relativePath.Length;

    if (Ctx != NULL && Ctx->IsFat32) {
        if (RtlEqualUnicodeString(&relativePath, &gEfiBcdRel, TRUE)) {
            return TRUE;
        }
    }

    if (Ctx != NULL && Ctx->IsNtfs) {
        if (RtlEqualUnicodeString(&relativePath, &gSystemBootBcdRel, TRUE)) {
            return TRUE;
        }
        if (RtlEqualUnicodeString(&relativePath, &gSystem32BcdRel, TRUE)) {
            return TRUE;
        }
    }

    if (Ctx != NULL && Ctx->IsNtfs) {
        if (RtlEqualUnicodeString(&relativePath, &gMbrWinreBcdRel, TRUE)) return TRUE;
        if (RtlEqualUnicodeString(&relativePath, &gSystem32BcdRel, TRUE)) return TRUE;
        if (RtlEqualUnicodeString(&relativePath, &gMbrBcdRel, TRUE)) return TRUE;
    }

    return FALSE;
}

// Shared logic 
FLT_PREOP_CALLBACK_STATUS HandlePreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ BOOLEAN IsCreateOp
) {
    if (!gProtectionActive) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (IsCreateOp) {
        PACCESS_MASK desiredAccess = &Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        // Only inspect requests that want to modify/delete the file
        if (!FlagOn(*desiredAccess, FILE_WRITE_DATA) &&
            !FlagOn(*desiredAccess, FILE_APPEND_DATA) &&
            !FlagOn(*desiredAccess, DELETE) &&
            !FlagOn(*desiredAccess, WRITE_DAC) &&
            !FlagOn(*desiredAccess, WRITE_OWNER)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }
    else if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        if (infoClass != FileRenameInformation &&
            infoClass != FileRenameInformationEx &&
            infoClass != FileDispositionInformation &&
            infoClass != FileDispositionInformationEx) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    PINSTANCE_CONTEXT instanceCtx = NULL;
    FltGetInstanceContext(FltObjects->Instance, &instanceCtx);

    PFLT_FILE_NAME_INFORMATION nameInfo;
    NTSTATUS status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    if (!NT_SUCCESS(status)) {
        if (instanceCtx) FltReleaseContext(instanceCtx);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        if (instanceCtx) FltReleaseContext(instanceCtx);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (IsProtectedPath(nameInfo, instanceCtx)) {
        FltReleaseFileNameInformation(nameInfo);
        if (instanceCtx) FltReleaseContext(instanceCtx);

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    if (instanceCtx) FltReleaseContext(instanceCtx);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS PreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    return HandlePreOperation(Data, FltObjects, TRUE);
}

FLT_PREOP_CALLBACK_STATUS PreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    
    if (!gProtectionActive) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PVOID streamCtx = NULL;
    NTSTATUS status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, &streamCtx);
    
    if (NT_SUCCESS(status)) {
        // Context exists, meaning this stream belongs to a protected BCD file!
        FltReleaseContext(streamCtx);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS PreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    return HandlePreOperation(Data, FltObjects, FALSE);
}

// Callbacks, Teardowns, and Context Registration remain standard If any one says a Frickin word about the Registration nothing will happen
NTSTATUS InstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreCreate, NULL },
    { IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreWrite, NULL },
    { IRP_MJ_SET_INFORMATION, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreSetInformation, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_CONTEXT_REGISTRATION ContextNotifications[] = {
    { FLT_INSTANCE_CONTEXT, 0, NULL, sizeof(INSTANCE_CONTEXT), 'BcdI', NULL, NULL, NULL },
    { FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0,
    ContextNotifications, Callbacks,
    NULL, InstanceSetup, InstanceQueryTeardown, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    gProtectionActive = FALSE;
    if (gFilterHandle) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    // FIX: Dereference the pointer spent some time to figure it out :D
    if (InitSafeBootMode != NULL && *InitSafeBootMode != 0) {
        DriverObject->DriverUnload = DriverUnload;
        return STATUS_SUCCESS;
    }

     status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    gProtectionActive = TRUE;
    DriverObject->DriverUnload = NULL;
    

    return STATUS_SUCCESS;
}

/*
This Driver is meant to protect the BCD files but there is functionality loss 
If you do Shift + Restart 
you will boot to WinRE 
BUT without any of the options the only option is to boot to UEFI mode 
And you no longer can edit the BCD while booting normally 
you have to boot to safe mode to do so
So Dual boot or writing new flags to the BCD will have a MINOR just a MINOR inconvenience because you must hard shut down 
the OS twice
By loading this driver you accept the functionality loos 
and all other False positives that may be triggered
Thanks for Viewing/loading BCDGuard 
and Viewing/Loading Salah-Code-Lab Solutions
remember Stay safe ! 
and yes i repeated it twice to REMIND DUMBASSES 
*/