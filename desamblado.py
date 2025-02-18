import capstone
import pefile

# Ruta del ejecutable
exe_path = "C:\\Users\\marce\\Downloads\\examples\\sample_qwrty_dk2_unpacked.exe"
output_file = "C:\\Users\\marce\\Downloads\\examples\\sample_qwrty_dk2_unpacked_disasm.txt"

# Cargar el archivo PE
pe = pefile.PE(exe_path)

# Buscar la sección .text
text_section = None
for section in pe.sections:
    if b".text" in section.Name:
        text_section = section
        break

if text_section:
    print(f"\n[+] Sección .text encontrada:")
    print(f"    Tamaño: {text_section.SizeOfRawData} bytes")
    print(f"    Dirección: {hex(text_section.VirtualAddress)}")

    # Leer el código de la sección .text
    with open(exe_path, "rb") as f:
        f.seek(text_section.PointerToRawData)
        code = f.read(text_section.SizeOfRawData)

    # Inicializar Capstone para x86
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    # Guardar el ensamblador en un archivo
    with open(output_file, "w") as out_file:
        out_file.write("[+] Código ensamblador de la sección .text:\n\n")
        for i in md.disasm(code, text_section.VirtualAddress):
            line = f"0x{i.address:x}: {i.mnemonic} {i.op_str}\n"
            out_file.write(line)
    
    print(f"[+] Código ensamblador guardado en: {output_file}")
else:
    print("\n[!] No se encontró la sección .text.")
