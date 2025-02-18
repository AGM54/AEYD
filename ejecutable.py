import magic

file_path = "C:\\Users\\marce\\Downloads\\examples\\sample_vg655_25th.exe"
file_type = magic.from_file(file_path)
print(f"Tipo de archivo: {file_type}")
