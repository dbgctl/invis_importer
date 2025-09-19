#include <ntifs.h>
#include <windef.h>

#include "invis_importer.h"

void UnloadDriver(PDRIVER_OBJECT driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);
    return;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(registry_path);

    driver_object->DriverUnload = UnloadDriver;

    II_CALL(DbgPrintEx, DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "hello");

    return STATUS_SUCCESS;
}
