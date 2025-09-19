# invis_importer

A simple C++20 header-only import-resolving library, with support for both kernel and user mode.

## Features

* Hides traces of imported functions, in both compiled application binary and runtime memory.

* Dual-mode support for a wide range of applicable usecases in usermode applications, kernel drivers, and type 2 hypervisors.

* Header-only format with macros for ease of installation and use.

* Cross-compiler compatibility in usermode for MSVC and Clang on Windows.

## Example usage

### Kernelmode:

```cpp
#include <ntifs.h>

#include "invis_importer.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(registry_path);
    UNREFERENCED_PARAMETER(driver_object);

    II_CALL(DbgPrintEx, DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "hello everyone!");

    return STATUS_SUCCESS;
}
```

### Usermode:

```cpp
#include <Windows.h>

#include "invis_importer.h"

int main()
{
    II_CALL(LoadLibraryA, "user32.dll");
    II_CALL(MessageBoxA, 0ull, "success!", "success!", 0ull);

    return 0;
}
```
> ***Note:*** **Import's module** must be **loaded first**.

## How it works

### Kernelmode:

In kernelmode it first executes a SIDT instruction via the __sidt compiler intrinsic to retrieve the interrupt designator table:

```cpp
unsigned long long get_idt_base() {

    SEGMENT_DESCRIPTOR_REGISTER_ idtr;
    __sidt(&idtr);

    return idtr.BaseAddress;
}
```

Every major interrupt's descriptor is located inside ntoskrnl, and ntoskrnl is always allocated on 2-megabyte large parges. With this in mind it then walks backwards 2 megabytes at a time, checking the start of each page until it locates a PE header - which identifies the base address of ntoskrnl:

```cpp
 unsigned long long get_kernel_base() {

    static unsigned long long ntoskrnl_base = 0;

    if (!ntoskrnl_base)
    {
        // this just dereferences the first interrupt descriptor
        SEGMENT_DESCRIPTOR_INTERRUPT_GATE_* interrupt_segment = (SEGMENT_DESCRIPTOR_INTERRUPT_GATE_*)get_idt_base();

        unsigned long long interrupt_handler_addr = 0;

        // reconstruct the address of it
        interrupt_handler_addr |= (unsigned long long)interrupt_segment->OffsetLow;              
        interrupt_handler_addr |= (unsigned long long)interrupt_segment->u.OffsetMiddle << 16;      
        interrupt_handler_addr |= (unsigned long long)interrupt_segment->OffsetHigh << 32;    

        // on x64 ntoskrnl will always be allocated on 2mb big pages
        unsigned long long curbase  = PAGE_ALIGN_BIG(interrupt_handler_addr);
        pe::IMAGE_DOS_HEADER_* dos  = (pe::IMAGE_DOS_HEADER_*)curbase;
        pe::IMAGE_NT_HEADERS_* nt   = (pe::IMAGE_NT_HEADERS_*)(curbase + dos->e_lfanew);

        // check valid pe format, if its valid it is the baseaddress
        while (dos->e_magic != 0x5A4D || nt->Signature != 0x4550) 
        {
            curbase -= PAGE_SIZE_BIG;
            dos = (pe::IMAGE_DOS_HEADER_*)curbase;
            nt = (pe::IMAGE_NT_HEADERS_*)(curbase + dos->e_lfanew);
        }

        ntoskrnl_base = curbase;
    }

    return ntoskrnl_base;
}
```

With the base address of ntoskrnl, it then grabs PsLoadedModuleList by iterating ntoskrnl's Export Address Table (EAT). From there it iterates the loaded drivers list, and checks each for the specified import via the EAT:

```cpp
template <unsigned long long hash>
unsigned long long find_exported_function()
{
    static PLIST_ENTRY_ loaded_modules_list = 0;
        
    if (!loaded_modules_list)
        loaded_modules_list = (PLIST_ENTRY_)pe::get_export< hash_str("PsLoadedModuleList") ^ hash_str(__DATE__)>(get_kernel_base());

    PLIST_ENTRY_ list_entry_first = loaded_modules_list;
    PLDR_DATA_TABLE_ENTRY_ ldr_table_entry = (PLDR_DATA_TABLE_ENTRY_)list_entry_first;

    do {

        unsigned long long export_address = pe::get_export<hash>(ldr_table_entry->base_address);
        if (export_address)
            return export_address;

        ldr_table_entry = (PLDR_DATA_TABLE_ENTRY_)ldr_table_entry->load_order_links.flink;

    } while ((void*)ldr_table_entry != (void*)list_entry_first);

    return 0;
}
```
> ***Note:*** **PsLoadedModuleList** contains **ntoskrnl.exe**.

### Usermode:

In usermode it resolves functions via the Process Environment Block (PEB), using the load order module linked list to iterate through each loaded module in the process:

```cpp
PPEB_ peb = (PPEB_)read_gs(0x60);

PLIST_ENTRY_ list_entry_first = &peb->ldr->load_order_module_list;
PLDR_DATA_TABLE_ENTRY_ ldr_table_entry = (PLDR_DATA_TABLE_ENTRY_)list_entry_first;

do {

    unsigned long long export_address = pe::get_export<hash>(ldr_table_entry->base_address);
    if (export_address)
        return export_address;

    ldr_table_entry = (PLDR_DATA_TABLE_ENTRY_)ldr_table_entry->load_order_links.flink;

} while ((void*)ldr_table_entry != (void*)list_entry_first);
```

For each loaded module, it uses the base address field in the table entry to get the module's PE header. With this it resolves the Export Address Table (EAT) and finds the specified function, adding the relative offset from the base to get the absolute address in memory:

```cpp
template <unsigned long long hash>
INVIS_IMPORTER_FORCEINLINE unsigned long long get_export(unsigned long long base)
{
    if (!base)
        return 0;

    PEXPORT_DIRECTORY_TABLE_ export_table = (PEXPORT_DIRECTORY_TABLE_)(base + PE_HEADER_(base)->OptionalHeader.DataDirectory[0].VirtualAddress);
    unsigned long* functions_table = (unsigned long*)(base + export_table->AddressOfFunctions);
    unsigned long* names_table = (unsigned long*)(base + export_table->AddressOfNames);
    unsigned short* ordinals_table = (unsigned short*)(base + export_table->AddressOfNameOrdinals);

    for (unsigned long i = 0; i < export_table->NumberOfFunctions; ++i)
    {
        if ((hash_str_runtime((const char*)(base + names_table[i])) ^ hash_str(__DATE__) ) == hash)
            return base + functions_table[ordinals_table[i]];
    }

    return 0;
}
```

## Other considerations

### Application security
The core purpose of this library is to make reverse-engineering of applications more difficult. By dynamically resolving imports from other modules, there will no longer be entries in the Import Address Table (IAT) of the output portable executable - making static analysis of core API calls more difficult to pin down and track without more invasive analysis at runtime.

To counter the aforementioned runtime analysis, any cached addresses are hashed in memory, and unhashed to their original values in temporary memory when they are required to be read. This prevents a reverse-engineer from simply scanning a process's memory for different import addresses to see what accesses them.

get_export is marked as force inline, meaning that a reverse-engineer cannot easily cross-reference the get_export function and find every instance where an import is resolved. If force inline is unavailable, get_export also takes a template hash of the function that is to be resolved, this is of course used to resolve the import - however also serves another purpose. Different uses of get_export will contain different hashes, and the compiler will output a different get_export function for each function that is to be resolved - again preventing ease of cross-referencing in static analysis.

### Hashing algorithms
Custom hashing algorithms can be easily implemented by swapping out the two defined hash keys.