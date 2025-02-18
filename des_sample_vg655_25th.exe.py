import capstone
import pefile

executables = {
    "sample_vg655_25th.exe": "C:\\Users\\marce\\Downloads\\examples\\sample_vg655_25th.exe"
}

for exe_name, exe_path in executables.items():
    output_file = f"{exe_name}_disassembly.txt"
    
    with open(output_file, "w", encoding="utf-8") as out:
        out.write(f"Desensamblando: {exe_name}\n\n")

        try:
            pe = pefile.PE(exe_path)
            out.write("Secciones del ejecutable:\n")
            for section in pe.sections:
                out.write(f"{section.Name.decode().strip()} - Tamaño: {section.SizeOfRawData} bytes - Dirección: {hex(section.VirtualAddress)}\n")
            
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            base_address = pe.OPTIONAL_HEADER.ImageBase
            entry_offset = entry_point + base_address

            out.write(f"\n Entry Point: {hex(entry_point)}\n")
            out.write(f" Dirección Base: {hex(base_address)}\n")
            out.write(f" Dirección de ejecución: {hex(entry_offset)}\n\n")

            with open(exe_path, "rb") as f:
                f.seek(entry_point)
                code = f.read(500)  
            
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            out.write(" Código ensamblador:\n")
            for i in md.disasm(code, entry_offset):
                out.write(f"0x{i.address:x}: {i.mnemonic} {i.op_str}\n")
            
            if not code:
                out.write("\n[!] No se obtuvo código ensamblador. Puede estar cifrado o en otra sección.\n")

        except Exception as e:
            out.write(f"[!] Error analizando {exe_name}: {e}\n")
    
    print(f" Resultado guardado en {output_file}")
