package crypto

import "fmt"

// SafeDecrypt ejecuta el descifrado AES-256-GCM en modo fail-closed:
//   - Ciphertext/tag manipulado, llave incorrecta o nonce alterado -> ErrAuthenticationFailed.
//   - Llave o nonce con longitud inválida -> ErrInvalidKeyLength / ErrInvalidNonceLength.
//   - Un pánico inesperado se recupera y se reporta como error, sin tumbar la aplicación.
//
// Ante cualquier error el plaintext retornado es siempre nil: nunca se exponen bytes parciales.
func SafeDecrypt(ciphertext, key, nonce []byte) (plaintext []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			plaintext, err = nil, fmt.Errorf("%w: recovered panic: %v", ErrAuthenticationFailed, r)
		}
	}()

	plaintext, err = NewAESGCMDecryptor().Decrypt(ciphertext, key, nonce)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
