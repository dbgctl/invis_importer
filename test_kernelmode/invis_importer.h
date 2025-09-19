#ifndef INVIS_IMPORTER_HPP
#define INVIS_IMPORTER_HPP

#define II_CALL(function, ...) invis_importer::find_and_call_function< invis_importer::hash_str(#function) ^ invis_importer::hash_str(__DATE__), decltype(&function) >(__VA_ARGS__ )
#define II_EXPORT(function, ...) invis_importer::find_export< invis_importer::hash_str(#function) ^ invis_importer::hash_str(__DATE__), decltype(&function) >()

namespace invis_importer
{

#if defined( __clang__ )

#define INVIS_IMPORTER_FORCEINLINE inline __attribute__((always_inline))

#else

#define INVIS_IMPORTER_FORCEINLINE __forceinline
#include <intrin.h>

#endif

    constexpr unsigned long long HASH_BASE = 0x2847228387475423ull;
    constexpr unsigned long long HASH_ADD = 0x2847228387475423ull;

    // compile time string hashing 
    template< typename T >
    consteval unsigned long long hash_str(const T* str) 
    {
        // hashing base
        unsigned long long hash = HASH_BASE;

        // can be complicated, just have it return the same value,
        // when called with the same parameters across multiple compilations
        for (int i = 0; str[i]; i++)
            hash ^= (unsigned char)(str[i]) * i * HASH_ADD;
        //       we cast this ^ to an unsigned char so that its only the lower 8 bits being hashed
        // this is so widestring and normal string variants of the same text remain the same hash 

        return hash;
    }

    // same thing as before 1:1, just in runtime instead of compile time
    template< typename T >
    INVIS_IMPORTER_FORCEINLINE unsigned long long hash_str_runtime(T* str)
    {
        unsigned long long hash = HASH_BASE;

        for (int i = 0; str[i]; i++)
            hash ^= (unsigned char)(str[i]) * i * HASH_ADD;

        return hash;
    }

    namespace pe
    {
        typedef struct _IMAGE_DOS_HEADER_
        {
            unsigned short e_magic;                     // Magic number
            unsigned short e_cblp;                      // Bytes on last page of file
            unsigned short e_cp;                        // Pages in file
            unsigned short e_crlc;                      // Relocations
            unsigned short e_cparhdr;                   // Size of header in paragraphs
            unsigned short e_minalloc;                  // Minimum extra paragraphs needed
            unsigned short e_maxalloc;                  // Maximum extra paragraphs needed
            unsigned short e_ss;                        // Initial (relative) SS value
            unsigned short e_sp;                        // Initial SP value
            unsigned short e_csum;                      // Checksum
            unsigned short e_ip;                        // Initial IP value
            unsigned short e_cs;                        // Initial (relative) CS value
            unsigned short e_lfarlc;                    // File address of relocation table
            unsigned short e_ovno;                      // Overlay number
            unsigned short e_res[4];                    // Reserved words
            unsigned short e_oemid;                     // OEM identifier (for e_oeminfo)
            unsigned short e_oeminfo;                   // OEM information; e_oemid specific
            unsigned short e_res2[10];                  // Reserved words
            int e_lfanew;                     // File address of new exe header
        } IMAGE_DOS_HEADER_, * PIMAGE_DOS_HEADER_;

        typedef struct _IMAGE_FILE_HEADER_
        {
            unsigned short Machine;
            unsigned short NumberOfSections;
            unsigned int TimeDateStamp;
            unsigned int PointerToSymbolTable;
            unsigned int NumberOfSymbols;
            unsigned short SizeOfOptionalHeader;
            unsigned short Characteristics;
        } IMAGE_FILE_HEADER_, * PIMAGE_FILE_HEADER_;

        typedef struct _IMAGE_DATA_DIRECTORY_
        {
            unsigned int VirtualAddress;
            unsigned int Size;
        } IMAGE_DATA_DIRECTORY_, * PIMAGE_DATA_DIRECTORY_;

        typedef struct _IMAGE_OPTIONAL_HEADER64
        {
            unsigned short Magic;
            unsigned char MajorLinkerVersion;
            unsigned char MinorLinkerVersion;
            unsigned int SizeOfCode;
            unsigned int SizeOfInitializedData;
            unsigned int SizeOfUninitializedData;
            unsigned int AddressOfEntryPoint;
            unsigned int BaseOfCode;
            unsigned long long ImageBase;
            unsigned int SectionAlignment;
            unsigned int FileAlignment;
            unsigned short MajorOperatingSystemVersion;
            unsigned short MinorOperatingSystemVersion;
            unsigned short MajorImageVersion;
            unsigned short MinorImageVersion;
            unsigned short MajorSubsystemVersion;
            unsigned short MinorSubsystemVersion;
            unsigned int Win32VersionValue;
            unsigned int SizeOfImage;
            unsigned int SizeOfHeaders;
            unsigned int CheckSum;
            unsigned short Subsystem;
            unsigned short DllCharacteristics;
            unsigned long long SizeOfStackReserve;
            unsigned long long SizeOfStackCommit;
            unsigned long long SizeOfHeapReserve;
            unsigned long long SizeOfHeapCommit;
            unsigned int LoaderFlags;
            unsigned int NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY_ DataDirectory[16];
        } IMAGE_OPTIONAL_HEADER64_, * PIMAGE_OPTIONAL_HEADER64_;

        typedef struct _IMAGE_NT_HEADERS_
        {
            unsigned int Signature;
            IMAGE_FILE_HEADER_ FileHeader;
            IMAGE_OPTIONAL_HEADER64_ OptionalHeader;
        } IMAGE_NT_HEADERS_, * PIMAGE_NT_HEADERS_;

        typedef struct _IMAGE_SECTION_HEADER
        {
            unsigned char Name[8];
            union
            {
                unsigned int PhysicalAddress;
                unsigned int VirtualSize;
            } Misc;
            unsigned int VirtualAddress;
            unsigned int SizeOfRawData;
            unsigned int PointerToRawData;
            unsigned int PointerToRelocations;
            unsigned int PointerToLinenumbers;
            unsigned short NumberOfRelocations;
            unsigned short NumberOfLinenumbers;
            unsigned int Characteristics;
        } IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

        typedef struct _EXPORT_DIRECTORY_TABLE_ {
            unsigned long   Characteristics;
            unsigned long   TimeDateStamp;
            unsigned short  MajorVersion;
            unsigned short  MinorVersion;
            unsigned long   Name;
            unsigned long   Base;
            unsigned long   NumberOfFunctions;
            unsigned long   NumberOfNames;
            unsigned long   AddressOfFunctions;     // RVA from base of image
            unsigned long   AddressOfNames;         // RVA from base of image
            unsigned long   AddressOfNameOrdinals;  // RVA from base of image
        } EXPORT_DIRECTORY_TABLE_, * PEXPORT_DIRECTORY_TABLE_;

#ifndef PE_HEADER_
#define PE_HEADER_(image) ((IMAGE_NT_HEADERS_*)((unsigned long long)image + ((IMAGE_DOS_HEADER_*)image)->e_lfanew))
#endif

#define CONTAINING_RECORD_(address, type, field) ((type *)( \
                                                  (char*)(address) - \
                                                  (unsigned long long)(&((type *)0)->field)))

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
    }

    typedef struct _LIST_ENTRY_
    {
        _LIST_ENTRY_* flink;
        _LIST_ENTRY_* blink;

    } LIST_ENTRY_, * PLIST_ENTRY_;

    typedef struct _UNICODE_STRING_
    {
        unsigned short length;
        unsigned short max_length;
        unsigned short* buffer;

    } UNICODE_STRING_, * PUNICODE_STRING_;

    typedef struct _LDR_DATA_TABLE_ENTRY_
    {
        LIST_ENTRY_ load_order_links;
        LIST_ENTRY_ memory_order_links;
        LIST_ENTRY_ initialization_order_links;
        unsigned long long base_address;
        unsigned long long entry_point;
        unsigned long size_of_image;
        char pad[4]; // pad to 8 byte alignment 
        UNICODE_STRING_ full_dll_name;
        UNICODE_STRING_ base_dll_name;

    } LDR_DATA_TABLE_ENTRY_, * PLDR_DATA_TABLE_ENTRY_;

#ifndef _KERNEL_MODE

    typedef struct _PEB_LDR_DATA_
    {
        unsigned char pad[0x10];
        LIST_ENTRY_ load_order_module_list;
        LIST_ENTRY_ memory_order_module_list;

    } PEB_LDR_DATA_, * PPEB_LDR_DATA_;

    typedef struct _PEB_
    {
        unsigned char pad[0x18];
        PPEB_LDR_DATA_ ldr;

    } PEB_, * PPEB_;

    INVIS_IMPORTER_FORCEINLINE unsigned long long read_gs(unsigned long offset)
    {

#if defined(__clang__)
        unsigned long long value;

        // x64 inline assembly supported here
        __asm__ volatile ("movq %%gs:(%1), %0" : "=r" (value) : "r" (offset) : "memory");
        return value;
#else
        return __readgsqword(offset);
#endif
    }

    // this is usermode version of it
    template <unsigned long long hash>
    unsigned long long find_exported_function()
    {
        // this offset is static across windows versions
        PPEB_ peb = (PPEB_)read_gs(0x60);

        PLIST_ENTRY_ list_entry_first = &peb->ldr->load_order_module_list;
        PLDR_DATA_TABLE_ENTRY_ ldr_table_entry = (PLDR_DATA_TABLE_ENTRY_)list_entry_first;

        do 
        {
            unsigned long long export_address = pe::get_export<hash>(ldr_table_entry->base_address);
            if (export_address)
                return export_address;

            ldr_table_entry = (PLDR_DATA_TABLE_ENTRY_)ldr_table_entry->load_order_links.flink;

        } while ((void*)ldr_table_entry != (void*)list_entry_first);

        return 0;
    }

#else

    // prevent auto stack align from compiler
#pragma pack(push, 1)
    typedef struct
    {
        unsigned short Limit;
        unsigned long long BaseAddress;
    } SEGMENT_DESCRIPTOR_REGISTER_;
#pragma pack(pop)

    typedef struct
    {
        unsigned short OffsetLow;
        unsigned short SegmentSelector;
        union
        {
            struct
            {
                unsigned int InterruptStackTable : 3;
                unsigned int MustBeZero0 : 5;
                unsigned int Type : 4;
                unsigned int MustBeZero1 : 1;
                unsigned int DescriptorPrivilegeLevel : 2;
                unsigned int Present : 1;
                unsigned int OffsetMiddle : 16;
            } u;

            unsigned int AsUInt;
        };

        unsigned int OffsetHigh;
        unsigned int Reserved;
    } SEGMENT_DESCRIPTOR_INTERRUPT_GATE_;

    unsigned long long get_idt_base() 
    {
        SEGMENT_DESCRIPTOR_REGISTER_ idtr;
        __sidt(&idtr);

        return idtr.BaseAddress;
    }

#define PAGE_SIZE_BIG 0x200000ull
#define PAGE_ALIGN_BIG(Va) ((unsigned long long)(Va) & ~(PAGE_SIZE_BIG - 1ull))

    unsigned long long get_kernel_base() 
    {
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

    // this is the kernelmode version of it
    template <unsigned long long hash>
    unsigned long long find_exported_function()
    {
        static PLIST_ENTRY_ loaded_modules_list = 0;
        
        if (!loaded_modules_list)
            loaded_modules_list = (PLIST_ENTRY_)pe::get_export< hash_str("PsLoadedModuleList") ^ hash_str(__DATE__)>(get_kernel_base());

        PLIST_ENTRY_ list_entry_first = loaded_modules_list;
        PLDR_DATA_TABLE_ENTRY_ ldr_table_entry = (PLDR_DATA_TABLE_ENTRY_)list_entry_first;

        do 
        {
            unsigned long long export_address = pe::get_export<hash>(ldr_table_entry->base_address);
            if (export_address)
                return export_address;

            ldr_table_entry = (PLDR_DATA_TABLE_ENTRY_)ldr_table_entry->load_order_links.flink;

        } while ((void*)ldr_table_entry != (void*)list_entry_first);

        return 0;
    }

#endif

    template <unsigned long long hash, typename T = unsigned long long>
    INVIS_IMPORTER_FORCEINLINE T find_export() 
    {
        static unsigned long long export_address = 0;

        // we hash it when we set it so people cant just scan for an export in our app's memory and replace it with their hook
        if (!export_address)
            export_address = find_exported_function<hash>() ^ hash;

        // return decrypted
        return (T)(export_address ^ hash);
    }

    template <unsigned long long hash, typename T, typename... VA>
    INVIS_IMPORTER_FORCEINLINE T find_and_call_function(VA... ARGS) 
    {
        using calltype = T(*)(VA...);
        return find_export<hash, calltype>()(ARGS...);
    }

}

#endif