package hcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// LinuxModuleSHA256 hashes the kernel's executable reference, including an old
// inode after a package replacement. It never hashes a caller-selected path.
// Failure leaves ATS identity unavailable; it is not ordinary tunnel health.
func LinuxModuleSHA256(ctx context.Context) string {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<30 {
		return ""
	}
	hash := sha256.New()
	buffer := make([]byte, 128*1024)
	var total int64
	for {
		if ctx.Err() != nil {
			return ""
		}
		count, readErr := file.Read(buffer)
		total += int64(count)
		if total > info.Size() {
			return ""
		}
		_, _ = hash.Write(buffer[:count])
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return ""
		}
	}
	after, err := file.Stat()
	if err != nil || total != info.Size() || after.Size() != info.Size() ||
		!after.ModTime().Equal(info.ModTime()) {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}
