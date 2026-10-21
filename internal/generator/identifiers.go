package generator

import (
	"crypto/rand"
	"fmt"
)

// GenerateUUIDv4 genera un UUID versión 4 compatible con RFC 4122 usando crypto/rand nativo
func GenerateUUIDv4() (string, error) {
	var uuid [16]byte
	_, err := rand.Read(uuid[:])
	if err != nil {
		return "", fmt.Errorf("failed to read secure random bytes: %w", err)
	}
	// RFC 4122: versión 4 en bits 4-7 del byte 6
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// RFC 4122: variante en bits 6-7 del byte 8 (10xxxxxx)
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

func GenerateStudentUID() string {
	return "STU-" + mustUUIDv4()
}

func GenerateProfessorUID() string {
	return "DOC-" + mustUUIDv4()
}

func GenerateSubjectUID() string {
	return "SUB-" + mustUUIDv4()
}

type SubjectCatalogItem struct {
	SubjectUID string
	Name       string
	Code       string
}

var DefaultSubjectCatalog = []SubjectCatalogItem{
	{SubjectUID: "SUB-750001C-CRIPTO", Name: "Criptografía y Seguridad", Code: "750001C"},
	{SubjectUID: "SUB-750002C-BD", Name: "Bases de Datos", Code: "750002C"},
	{SubjectUID: "SUB-750003C-ED", Name: "Estructuras de Datos", Code: "750003C"},
	{SubjectUID: "SUB-750004C-REDES", Name: "Redes y Telecomunicaciones", Code: "750004C"},
	{SubjectUID: "SUB-750005C-SO", Name: "Sistemas Operativos", Code: "750005C"},
}
