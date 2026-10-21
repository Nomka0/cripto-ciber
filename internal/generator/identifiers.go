package generator

import (
	"crypto/rand"
	"fmt"
)

// GenerateUUIDv4 genera un UUID versión 4 compatible con RFC 4122 usando crypto/rand
func GenerateUUIDv4() (string, error) {
	var uuid [16]byte
	_, err := rand.Read(uuid[:])
	if err != nil {
		return "", err
	}
	// Set version (4) and variant (RFC 4122)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}

func mustUUIDv4() string {
	id, err := GenerateUUIDv4()
	if err != nil {
		panic(err)
	}
	return id
}

// GenerateStudentUID genera un identificador sintético con prefijo STU-<uuid>
func GenerateStudentUID() string {
	return "STU-" + mustUUIDv4()
}

// GenerateProfessorUID genera un identificador sintético con prefijo DOC-<uuid>
func GenerateProfessorUID() string {
	return "DOC-" + mustUUIDv4()
}

// GenerateSubjectUID genera un identificador sintético con prefijo SUB-<uuid>
func GenerateSubjectUID() string {
	return "SUB-" + mustUUIDv4()
}

// GenerateEventUID genera un identificador sintético con prefijo EVT-<uuid>
func GenerateEventUID() string {
	return "EVT-" + mustUUIDv4()
}

// SubjectCatalogItem representa una materia en el catálogo predefinido
type SubjectCatalogItem struct {
	SubjectUID string
	Name       string
	Code       string
}

// DefaultSubjectCatalog catálogo precargado de materias comunes
var DefaultSubjectCatalog = []SubjectCatalogItem{
	{SubjectUID: "SUB-750001C-CRIPTO", Name: "Criptografía y Seguridad", Code: "750001C"},
	{SubjectUID: "SUB-750002C-BD", Name: "Bases de Datos", Code: "750002C"},
	{SubjectUID: "SUB-750003C-ED", Name: "Estructuras de Datos", Code: "750003C"},
	{SubjectUID: "SUB-750004C-REDES", Name: "Redes y Telecomunicaciones", Code: "750004C"},
	{SubjectUID: "SUB-750005C-SO", Name: "Sistemas Operativos", Code: "750005C"},
}

// PreloadedSubjectCatalog mapea materias comunes a sus respectivos UIDs
var PreloadedSubjectCatalog = map[string]string{
	"Criptografía y Seguridad":   "SUB-750001C-CRIPTO",
	"Bases de Datos":             "SUB-750002C-BD",
	"Estructuras de Datos":       "SUB-750003C-ED",
	"Redes y Telecomunicaciones": "SUB-750004C-REDES",
	"Sistemas Operativos":        "SUB-750005C-SO",
}
