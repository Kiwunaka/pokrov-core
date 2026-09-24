//go:build android && cgo

package hcore

/*
#cgo LDFLAGS: -ldl
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    char path[4097];
    uintptr_t address;
    uintptr_t base;
} pokrov_module_location;

static pokrov_module_location pokrov_locate_module(void) {
    pokrov_module_location result = {0};
    Dl_info info;
    uintptr_t address = (uintptr_t)&pokrov_locate_module;
    if (!dladdr((void *)address, &info) || !info.dli_fname) return result;
    size_t length = strnlen(info.dli_fname, sizeof(result.path));
    if (!length || length >= sizeof(result.path)) return result;
    memcpy(result.path, info.dli_fname, length);
    result.address = address;
    result.base = (uintptr_t)info.dli_fbase;
    return result;
}
*/
import "C"

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var androidModuleIdentity struct {
	once sync.Once
	digest string
}

// AndroidModuleSHA256 observes the ELF containing this function, not the APK
// container or a caller-selected library. Gomobile retains this module for the
// process lifetime. Missing identity does not change ordinary Core health.
func AndroidModuleSHA256() string {
	androidModuleIdentity.once.Do(func() {
		androidModuleIdentity.digest = readAndroidModuleSHA256()
	})
	return androidModuleIdentity.digest
}

type androidModuleMapping struct {
	start, end, offset, major, minor, inode uint64
}

func androidMappingAt(address uint64) (androidModuleMapping, bool) {
	file, err := os.Open("/proc/self/maps")
	if err != nil { return androidModuleMapping{}, false }
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 16<<20))
	scanner.Buffer(make([]byte, 4096), 16<<10)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 { return androidModuleMapping{}, false }
		bounds := strings.Split(fields[0], "-")
		device := strings.Split(fields[3], ":")
		if len(bounds) != 2 || len(device) != 2 { return androidModuleMapping{}, false }
		var row androidModuleMapping
		values := []*uint64{&row.start, &row.end, &row.offset, &row.major, &row.minor, &row.inode}
		for index, value := range []string{bounds[0], bounds[1], fields[2], device[0], device[1], fields[4]} {
			base := 16
			if index == 5 { base = 10 }
			parsed, parseErr := strconv.ParseUint(value, base, 64)
			if parseErr != nil { return androidModuleMapping{}, false }
			*values[index] = parsed
		}
		if address >= row.start && address < row.end {
			return row, row.inode != 0 && strings.Contains(fields[1], "x")
		}
	}
	return androidModuleMapping{}, false
}

func readAndroidModuleSHA256() string {
	location := C.pokrov_locate_module()
	path := C.GoString(&location.path[0])
	address, base := uint64(location.address), uint64(location.base)
	if path == "" || address < base || base == 0 { return "" }
	mapping, ok := androidMappingAt(address)
	if !ok { return "" }
	container, entry, inAPK := strings.Cut(path, "!/")
	file, err := os.Open(container)
	if err != nil { return "" }
	defer file.Close()
	var before unix.Stat_t
	if unix.Fstat(int(file.Fd()), &before) != nil || before.Mode & unix.S_IFMT != unix.S_IFREG ||
		before.Size <= 0 || before.Size > 2<<30 || uint64(before.Ino) != mapping.inode ||
		uint64(unix.Major(uint64(before.Dev))) != mapping.major ||
		uint64(unix.Minor(uint64(before.Dev))) != mapping.minor { return "" }
	start, size := int64(0), before.Size
	if inAPK {
		archive, zipErr := zip.NewReader(file, before.Size)
		if zipErr != nil { return "" }
		var match *zip.File
		for _, candidate := range archive.File {
			if candidate.Name == entry {
				if match != nil { return "" }
				match = candidate
			}
		}
		// Android directly maps only uncompressed native entries. Hash that ELF's
		// bytes, and bind its offset to the mapping below before accepting it.
		if match == nil || match.Method != zip.Store || match.UncompressedSize64 == 0 ||
			match.UncompressedSize64 > 1<<30 || match.CompressedSize64 != match.UncompressedSize64 { return "" }
		start, err = match.DataOffset()
		if err != nil { return "" }
		size = int64(match.UncompressedSize64)
	}
	if size <= 0 || size > 1<<30 || start < 0 || start > before.Size-size { return "" }
	section := io.NewSectionReader(file, start, size)
	image, err := elf.NewFile(section)
	if err != nil { return "" }
	defer image.Close()
	virtual := address-base
	matched := false
	for _, program := range image.Progs {
		if program.Type != elf.PT_LOAD || program.Flags & elf.PF_X == 0 ||
			virtual < program.Vaddr || virtual-program.Vaddr >= program.Filesz { continue }
		delta := virtual-program.Vaddr
		if program.Off >= uint64(size) || delta >= uint64(size)-program.Off { return "" }
		fileOffset := uint64(start)+program.Off+delta
		if fileOffset < mapping.offset || fileOffset-mapping.offset != address-mapping.start { return "" }
		matched = true
		break
	}
	if !matched { return "" }
	hash := sha256.New()
	count, err := io.CopyBuffer(hash, io.NewSectionReader(file, start, size), make([]byte, 128<<10))
	if err != nil || count != size { return "" }
	var after unix.Stat_t
	if unix.Fstat(int(file.Fd()), &after) != nil || before.Size != after.Size ||
		before.Mtim != after.Mtim || before.Ctim != after.Ctim { return "" }
	current, ok := androidMappingAt(address)
	if !ok || current != mapping { return "" }
	return hex.EncodeToString(hash.Sum(nil))
}
