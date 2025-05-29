#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <intrin.h>

extern void AsmEnableVmxOperation(void);
extern UINT32 AsmRdmsrWord(UINT32 msr);
extern INT64 AsmReadRegister(USHORT reg);

#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_QUERY_EA                 0x07
#define IRP_MJ_SET_EA                   0x08
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0a
#define IRP_MJ_SET_VOLUME_INFORMATION   0x0b
#define IRP_MJ_DIRECTORY_CONTROL        0x0c
#define IRP_MJ_FILE_SYSTEM_CONTROL      0x0d
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0f
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_LOCK_CONTROL             0x11
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_CREATE_MAILSLOT          0x13
#define IRP_MJ_QUERY_SECURITY           0x14
#define IRP_MJ_SET_SECURITY             0x15
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_DEVICE_CHANGE            0x18
#define IRP_MJ_QUERY_QUOTA              0x19
#define IRP_MJ_SET_QUOTA                0x1a
#define IRP_MJ_PNP                      0x1b
#define IRP_MJ_PNP_POWER                IRP_MJ_PNP // Obsolete....
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b

#define ALLOCATION_TAG                  'iali'

#define IA32_VMX_BASIC                  0x480
#define IA32_VMX_CR0_FIXED0             0x486
#define IA32_VMX_CR0_FIXED1             0x487
#define IA32_VMX_CR4_FIXED0             0x488
#define IA32_VMX_CR4_FIXED1             0x489

#define VM_INSTR_ERROR                  0x4400

enum ReadRegisters {CR0=0, CR1, CR2, CR3, CR4};
enum VmxInstructionResult {VMX_NOERROR, VMX_INSTR_ERROR, VMX_VMCS_ERROR};

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

VOID
DrvUnload(PDRIVER_OBJECT DriverObject);

NTSTATUS
DrvUnsupported(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DrvUnload)

UINT32 readmsr(UINT32 msr) {
    return (UINT32)(__readmsr(msr) & 0xFFFFFFFF);
}

NTSTATUS
DrvUnsupported(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[*] This function is not supported :( !");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[*] READ Not implemented yet :( !");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[*] WRITE Not implemented yet :( !");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[*] CLOSE Not implemented yet :( !");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static BOOLEAN vmxSucceeded(USHORT vmxResult, LPCSTR instructionName, BOOLEAN vmcsConfigured) {
    if (vmxResult == VMX_NOERROR) return TRUE;
    if (vmxResult == VMX_INSTR_ERROR) {
        if (vmcsConfigured) {
            SIZE_T failureReason = 0;
            __vmx_vmread(VM_INSTR_ERROR, &failureReason);
            DbgPrint("[!] %s failed with instruction error code [%lx]!", instructionName, (LONG)failureReason);
        } else DbgPrint("[!] %s failed with instruction error", instructionName);
    }
    else {
        DbgPrint("[!] %s failed because VMCS pointer is not valid!", instructionName);
    }
    return FALSE;
}

BOOLEAN StartVmx() {
    // Step 1 - Enable VMX.
    AsmEnableVmxOperation();

    // Step 2 - Assert valid bits.
    INT64 cr0 = AsmReadRegister(CR0), cr4 = AsmReadRegister(CR4);
    UINT32 cr0Fixed0 = readmsr(IA32_VMX_CR0_FIXED0), cr0Fixed1 = readmsr(IA32_VMX_CR0_FIXED1);
    UINT32 cr4Fixed0 = readmsr(IA32_VMX_CR4_FIXED0), cr4Fixed1 = readmsr(IA32_VMX_CR4_FIXED1);
    if ((~cr0) & cr0Fixed0) {
        DbgPrint("[!] CR0 bits not set! [%x]", (UINT32)((~cr0) & cr0Fixed0));
        return FALSE;
    }
    if (cr0 & (~cr0Fixed1)) {
        DbgPrint("[!] CR0 bits shouldn't be set! [%x]", (UINT32)(cr0 & (~cr0Fixed1)));
        return FALSE;
    }
    if ((~cr4) & cr4Fixed0) {
        DbgPrint("[!] CR4 bits not set! [%x]", (UINT32)((~cr4) & cr4Fixed0));
        return FALSE;
    }
    if (cr4 & (~cr4Fixed1)) {
        DbgPrint("[!] CR4 bits shouldn't be set! [%x]", (UINT32)(cr4 & (~cr4Fixed1)));
        return FALSE;
    }

    // Step 3 - Create VMXON region
    PVOID vmxonRegion = ExAllocatePool2(POOL_FLAG_PAGED, PAGE_SIZE, ALLOCATION_TAG);
    if (vmxonRegion == NULL) {
        DbgPrint("[!] Failed to allocatte VMXON region!");
        return FALSE;
    }
    *((PUINT32)vmxonRegion) = readmsr(IA32_VMX_BASIC);
    
    UINT64 vmxonAddr = MmGetPhysicalAddress(vmxonRegion).QuadPart;
    if (!vmxSucceeded(__vmx_on(&vmxonAddr), "VMXON", FALSE)) return FALSE;

    // Step 4 - Create VMCS region
    PVOID vmcsRegion = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, ALLOCATION_TAG);
    if (vmcsRegion == NULL) {
        DbgPrint("[!] Failed to allocatte VMCS region!");
        return FALSE;
    }
    *((PUINT32)vmcsRegion) = readmsr(IA32_VMX_BASIC); // Automatically sets the "shadow" bit (=bit 31) to 0.

    UINT64 vmcsAddr = MmGetPhysicalAddress(vmcsRegion).QuadPart;
    if (!vmxSucceeded(__vmx_vmclear(&vmcsAddr), "VMCLEAR", FALSE)) return FALSE;
    if (!vmxSucceeded(__vmx_vmptrld(&vmcsAddr), "VMPTRLD", FALSE)) return FALSE;
    return TRUE;
}

NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    if (StartVmx()) {
        DbgPrint("[*] VMX Operation Enabled Successfully !");
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
    else {
        DbgPrint("[-] VMX Operation Failed...");
        Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS
DrvIoctlDispatcher(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[*] IOCTL Not implemented yet :( !");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS       NtStatus = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING DriverName, DosDeviceName;
    UINT32 Index = 0; // TODO: Match windows convention.

    DbgPrint("DriverEntry Called.");

    RtlInitUnicodeString(&DriverName, L"\\Device\\MyHypervisor");
    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisor");

    NtStatus = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (NtStatus == STATUS_SUCCESS)
    {
        for (Index = 0; Index <= IRP_MJ_MAXIMUM_FUNCTION; Index++)
        {
            DriverObject->MajorFunction[Index] = DrvUnsupported;
        }

        DbgPrint("[*] Setting Devices major functions.");
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
        DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIoctlDispatcher;

        DriverObject->MajorFunction[IRP_MJ_READ] = DrvRead;
        DriverObject->MajorFunction[IRP_MJ_WRITE] = DrvWrite;

        DriverObject->DriverUnload = DrvUnload;
        // TODO: Maybe remove the following?
        DeviceObject->Flags |= IO_TYPE_DEVICE;
        DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
        IoCreateSymbolicLink(&DosDeviceName, &DriverName);
    }
    else
    {
        DbgPrint("[*] There were some errors in creating device.");
    }
    return NtStatus;
}

VOID
DrvUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING DosDeviceName;
    DbgPrint("DrvUnload Called !");

    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisor");

    IoDeleteSymbolicLink(&DosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);
}
