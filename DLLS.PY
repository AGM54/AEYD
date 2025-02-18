import pefile
from datetime import datetime


executables = {
    "sample_qwrty_dk2_unpacked.exe": "C:\\Users\\marce\\Downloads\\examples\\sample_qwrty_dk2_unpacked.exe",
    "sample_vg655_25th.exe": "C:\\Users\\marce\\Downloads\\examples\\sample_vg655_25th.exe"
}

for exe_name, exe_path in executables.items():
    print(f"\n{'='*30}")
    print(f" {exe_name}")
    print(f"{'='*30}")

    try:
        pe = pefile.PE(exe_path)

        compile_timestamp = pe.FILE_HEADER.TimeDateStamp
        compile_date = datetime.utcfromtimestamp(compile_timestamp)
        print(f"\n[+] Fecha de compilación: {compile_date}")

        
        print("\n[+] DLLs Importadas:")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"\nDLL: {entry.dll.decode()}")
            for imp in entry.imports:
                print(f"    {hex(imp.address)} - {imp.name.decode() if imp.name else 'Ordinal: ' + str(imp.ordinal)}")

    except Exception as e:
        print(f"\n[!] Error analizando {exe_name}: {e}")
