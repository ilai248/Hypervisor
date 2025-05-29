#include <windows.h> // For HANDLE, CreateFile
#include <intrin.h>  // For __cpuid
#include <string>    // For std::string
#include <iostream>  // For std::cout

std::string GetCpuID()
{
    int cpuInfo[4] = { 0 };
    char SysType[13] = { 0 };
    std::string CpuID;

    // Call CPUID with EAX=0 to get vendor string
    __cpuid(cpuInfo, 0);

    // Extract vendor string from EBX, EDX, ECX
    SysType[0] = (char)(cpuInfo[1] & 0xFF);        // EBX low byte
    SysType[1] = (char)((cpuInfo[1] >> 8) & 0xFF); // EBX high byte
    SysType[2] = (char)((cpuInfo[1] >> 16) & 0xFF);
    SysType[3] = (char)((cpuInfo[1] >> 24) & 0xFF);
    SysType[4] = (char)(cpuInfo[3] & 0xFF);        // EDX low byte
    SysType[5] = (char)((cpuInfo[3] >> 8) & 0xFF);
    SysType[6] = (char)((cpuInfo[3] >> 16) & 0xFF);
    SysType[7] = (char)((cpuInfo[3] >> 24) & 0xFF);
    SysType[8] = (char)(cpuInfo[2] & 0xFF);        // ECX low byte
    SysType[9] = (char)((cpuInfo[2] >> 8) & 0xFF);
    SysType[10] = (char)((cpuInfo[2] >> 16) & 0xFF);
    SysType[11] = (char)((cpuInfo[2] >> 24) & 0xFF);
    SysType[12] = 0;

    CpuID.assign(SysType, 12);
    return CpuID;
}

bool DetectVmxSupport()
{
    int cpuInfo[4] = { 0 };

    // Call CPUID with EAX=1 to get feature information
    __cpuid(cpuInfo, 1);

    // Check ECX bit 5 for VMX support
    return (cpuInfo[2] & (1 << 5)) != 0;
}

int main()
{
    std::string CpuId = GetCpuID();
    std::cout << "[*] The CPU Vendor is: " << CpuId << std::endl;

    if (CpuId == "GenuineIntel")
    {
        std::cout << "[*] The Processor virtualization technology is VT-x." << std::endl;
    }
    else
    {
        std::cout << "[*] This program is not designed to run in a non-VT-x environment!" << std::endl;
        return 1;
    }

    if (DetectVmxSupport())
    {
        std::cout << "[*] VMX Operation is supported by your processor." << std::endl;
    }
    else
    {
        std::cout << "[*] VMX Operation is not supported by your processor." << std::endl;
        return 1;
    }

    HANDLE hWnd = CreateFile(L"\\\\.\\MyHypervisor",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ |
        FILE_SHARE_WRITE,
        NULL, /// lpSecurityAttirbutes
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL |
        FILE_FLAG_OVERLAPPED,
        NULL); /// lpTemplateFile

    if (hWnd == INVALID_HANDLE_VALUE)
    {
        std::cout << "[*] Could not open device: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[*] Device opened successfully. Press any key to close..." << std::endl;
    getchar();
    CloseHandle(hWnd);
    return 0;
}
