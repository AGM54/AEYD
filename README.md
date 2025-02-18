# **README - Análisis de Ejecutables y Ensamblador**

## **Descripción del Proyecto**

Este proyecto tiene como objetivo analizar y desensamblar dos ejecutables sospechosos, verificar si están empaquetados, listar las DLLs y funciones utilizadas, y compararlas con comportamientos maliciosos documentados en el artículo "Malware classification based on API calls and behaviour analysis".

---

## **Archivos Incluidos**

### **1. Análisis de Ensamblador**

- **`des_sample_qwrty_dk2_unpacked.exe.py`** → Script utilizado para obtener el código ensamblador del ejecutable `sample_qwrty_dk2`.
- **`des_sample_vg655_25th.exe.py`** → Script utilizado para obtener el código ensamblador del ejecutable `sample_vg655_25th.exe`.
- **`sample_qwrty_dk2_ensamblado.txt`** → Contiene el código ensamblador obtenido del archivo `sample_qwrty_dk2`.
- **`ensamblador_sample_vg655_25th.exe.txt`** → Contiene el código ensamblador obtenido del archivo `sample_vg655_25th.exe`.

### **2. Análisis de Empaquetado**

- **`ejecutable.py`** → Script utilizado para determinar si los ejecutables están empaquetados. En caso positivo, intenta desempaquetarlos.

### **3. Análisis de DLLs y Funciones**

- **`DLLS.PY`** → Script que extrae y lista las DLLs y funciones utilizadas por los ejecutables.
- **Comparación con el artículo "Malware classification based on API calls and behaviour analysis"**
  - Se analiza la presencia de funciones sospechosas comparándolas con la **Tabla 3** del artículo.
  - Se justifica si hay indicios de comportamiento malicioso en base a esta comparación.

### **4. Reporte Final**

- **`Análisis.pdf`** → Documento con los hallazgos del análisis, incluyendo capturas de pantalla y explicaciones detalladas.

---

## **Instrucciones de Uso**

### **1. Obtener Código Ensamblador**

Ejecutar los siguientes scripts para obtener el código ensamblador de cada ejecutable:

```bash
python des_sample_qwrty_dk2_unpacked.exe.py
python des_sample_vg655_25th.exe.py
```

Los resultados se guardarán en los archivos `.txt` correspondientes.

### **2. Verificar Empaquetado**

Para determinar si los ejecutables están empaquetados:

```bash
python ejecutable.py
```

Si están empaquetados, el script intentará desempaquetarlos automáticamente.

### **3. Extraer DLLs y Funciones**

Para listar las DLLs y funciones utilizadas por los ejecutables:

```bash
python DLLS.PY
```

Se compararán con la Tabla 3 del artículo para detectar posibles comportamientos maliciosos.

---
