# Taller Dos – Criptografía
## PROTECCIÓN DE LOGS ESTRUCTURADOS EN REPOSO

### Introducción
En un sistema de gestión académica universitaria, el proceso de registro de notas y modificación de notas constituye una operación sensible desde la perspectiva de ciberseguridad e ingeniería de software. Una posible vulneración de estos eventos afecta la confianza en la información académica y, por tanto, requieren mecanismos que fortalezcan la trazabilidad, la integridad y la confidencialidad de los datos.

En este taller se trabajará con la noción de **datos en reposo**, centrándose en la generación y protección de un archivo simulado de logs estructurados que representa operaciones académicas sensibles. El propósito es diseñar e implementar un módulo que permita demostrar, mediante mecanismos criptográficos, que:

* El log generado puede protegerse frente a lectura no autorizada.
* Cualquier alteración del contenido puede ser detectada.
* El proceso de cifrado y descifrado preserva la información original.

---

### Objetivo General
Diseñar e implementar una herramienta CLI en Go que genere logs estructurados de eventos académicos de registro y modificación de notas y que aplique mecanismos de hashing y cifrado para proteger su integridad, confidencialidad y verificabilidad durante el ciclo de almacenamiento y recuperación.

---

### Resultados de Aprendizaje
* Entender el concepto de una operación sensible dentro de un dominio de negocio realista, desde la perspectiva de atributos y sub-atributos de seguridad.
* Diseñar un log estructurado en formato JSON para representar eventos de registro y modificación de notas, justificando la selección de campos, en pro de la satisfacción de los atributos de calidad considerados.
* Implementar operaciones de hashing y cifrado para brindar integridad a nivel de cada registro y confidencialidad de los registros en su totalidad.

---

### Descripción Funcional
La aplicación deberá guiar al usuario, a través de una interfaz CLI con menú interactivo, en un flujo de trabajo que contemple las siguientes acciones:

* **Paso 1. Definición del volumen de eventos:** la aplicación deberá solicitar al usuario la cantidad de eventos de log a generar.
* **Paso 2. Generación aleatoria de eventos:** la aplicación deberá generar aleatoriamente eventos de dos tipos: *registro de nota* y *modificación de nota*. Cada evento deberá estar representado mediante un objeto JSON estructurado y deberá incluir, como mínimo, identificadores de los actores, recursos y datos involucrados. El modelo deberá orientarse a identificadores únicos o pseudónimos (por ejemplo, UID). El valor de la nota deberá generarse aleatoriamente con distribución uniforme entre 0.0 y 5.0. En el caso de modificación de nota, el evento deberá permitir diferenciar entre el valor anterior y el nuevo valor.
* **Paso 3. Hash del payload de cada operación:** cada evento deberá incluir un hash del payload de la operación, incorporado dentro del mismo log. El reporte técnico de la solución deberá diseñar y justificar qué campos conforman dicho payload y cómo se excluyen del cálculo aquellos campos que harían circular la operación de hashing.
* **Paso 4. Construcción del log estructurado completo:** la aplicación deberá consolidar los eventos generados en un log estructurado en formato JSON. El diseño del esquema del log deberá ser propuesto y justificado por el equipo o estudiante.
* **Paso 5. Hash del log completo en claro/texto plano:** antes de cifrar el archivo, la aplicación deberá calcular el hash del log completo original y almacenarlo de forma separada.
* **Paso 6. Cifrado del log en reposo:** la aplicación deberá cifrar el log completo utilizando mecanismos criptográficos implementados con bibliotecas nativas de Go. El resultado deberá almacenarse como un artefacto separado del log original, así como los insumos requeridos para la operación criptográfica en su totalidad.
* **Paso 7. Hash del log cifrado:** la aplicación deberá calcular el hash del log cifrado y almacenarlo de forma separada.
* **Paso 8. Descifrado del log:** la aplicación deberá recuperar el contenido del log cifrado mediante descifrado, reconstruyendo el artefacto lógico original o su equivalente verificable.
* **Paso 9. Hash del log descifrado:** la aplicación deberá calcular el hash del log descifrado y compararlo con el hash del log original en claro.
* **Paso 10. Presentación de resultados:** la aplicación deberá informar de manera clara al usuario cantidad de eventos generados, tipo de eventos generados, hashes obtenidos en cada etapa, y resultado de la comparación entre log original y log descifrado. La salida deberá permitir concluir si el proceso preservó la información original.

---

### Restricciones Tecnológicas
La solución deberá respetar las siguientes restricciones:
* La implementación debe realizarse en **Go**.
* Para los mecanismos de hashing y criptográficos, se deberán emplear bibliotecas nativas o estándar de Go.
* La aplicación deberá ofrecer una interfaz CLI, guiada por menús y soportada en la reutilización de una librería de terceros orientada a interacción en terminal.

---

### Entregables
El equipo deberá cargar en la plataforma Moodle del curso un archivo `.ZIP` conteniendo:

1. **Archivo .ZIP** con estructura de carpetas de código fuente en Go, incluyendo 2 diagramas de diseño: uno de estructura y otro de comportamiento.
2. **Archivo .PDF** con diapositivas que comuniquen lo realizado en el taller y que sirva de apoyo para el video de sustentación y demostración del taller. Se deben incluir detalles y justificación de diseño y selección de funciones de hashing y criptrográficas. Incluir diapositiva de declaración de uso responsable de IA.
3. **Enlace URL a video de sustentación** del taller, incluido en las diapositivas del proyecto, en el que intervengan todos los integrantes del equipo de trabajo.
