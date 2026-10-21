package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
)

var ErrNilLog = errors.New("log cannot be nil")

// MarshalCanonical serializa una estructura en JSON canónico determinista
func MarshalCanonical(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SaveCanonicalLogToFile guarda el log consolidado en disco con permisos POSIX restringidos (0600)
func SaveCanonicalLogToFile(path string, log *ConsolidatedAcademicLog) error {
	if log == nil {
		return ErrNilLog
	}
	data, err := MarshalCanonical(log)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadCanonicalLogFromFile carga y deserializa el log canónico desde disco
func LoadCanonicalLogFromFile(path string) (*ConsolidatedAcademicLog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var log ConsolidatedAcademicLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, err
	}
	return &log, nil
}
