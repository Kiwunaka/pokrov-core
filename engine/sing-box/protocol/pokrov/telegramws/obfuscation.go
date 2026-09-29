package telegramws

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// Telegram's native obfuscated transport uses the raw key in its 64-byte
// initialization. MTProxy's secret-derived key and non-obfuscated transports
// are deliberately unsupported and keep their original VPN path.
// https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation
func nativeObfuscatedInitialization(initial []byte) bool {
	if len(initial) != 64 || initial[0] == 0xef || binary.LittleEndian.Uint32(initial[4:8]) == 0 {
		return false
	}
	switch string(initial[:4]) {
	case "HEAD", "POST", "GET ", "OPTI", "\xee\xee\xee\xee", "\xdd\xdd\xdd\xdd", "\x16\x03\x01\x02":
		return false
	}
	block, _ := aes.NewCipher(initial[8:40])
	decoded := make([]byte, 64)
	cipher.NewCTR(block, initial[40:56]).XORKeyStream(decoded, initial)
	switch binary.LittleEndian.Uint32(decoded[56:60]) {
	case 0xefefefef, 0xeeeeeeee, 0xdddddddd:
		return true
	default:
		return false
	}
}
