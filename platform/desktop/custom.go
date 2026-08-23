package main

/*
#include <stdlib.h>
#include <signal.h>
#include "stdint.h"

#if defined(_WIN32)
#define POKROV_CALL __cdecl
#else
#define POKROV_CALL
#endif

typedef void (POKROV_CALL *pokrov_core_event_callback_v1)(
    int schema_version,
    int event_abi,
    const char* occurred_at_utc,
    const char* run_id,
    const char* attempt_id,
    long long generation,
    long long sequence,
    const char* name,
    const char* subsystem,
    const char* stage,
    const char* severity,
    const char* outcome,
    const char* error_code,
    const char* phase);

static int pokrov_core_event_callback_is_null(
    pokrov_core_event_callback_v1 callback) {
  return callback == NULL;
}

static void pokrov_core_emit_event_v1(
    pokrov_core_event_callback_v1 callback,
    int schema_version,
    int event_abi,
    const char* occurred_at_utc,
    const char* run_id,
    const char* attempt_id,
    long long generation,
    long long sequence,
    const char* name,
    const char* subsystem,
    const char* stage,
    const char* severity,
    const char* outcome,
    const char* error_code,
    const char* phase) {
  if (callback != NULL) {
    callback(schema_version, event_abi, occurred_at_utc, run_id, attempt_id,
             generation, sequence, name, subsystem, stage, severity, outcome,
             error_code, phase);
  }
}
*/
import "C"

import (
	// "os"
	// "os/signal"

	"runtime"

	// "syscall"
	"unsafe"

	hcore "github.com/Kiwunaka/POKROV-core/v2/hcore"
	"github.com/Kiwunaka/POKROV-core/v2/hutils"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
)

// func init() {
// 	runtime.LockOSThread()
// 	C.init_signals()
// 	runtime.UnlockOSThread()

// 	go handleSignals()

// 	// Your other initialization code can go here
// }

// // Signal handling function
// func handleSignals() {
// 	signalChan := make(chan os.Signal, 1)
// 	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGURG)

// 	for {
// 		<-signalChan
// 		// switch sig {
// 		// case syscall.SIGINT, syscall.SIGTERM:
// 		// 	// runtime.LockOSThread() // Lock to the current OS thread
// 		// 	// defer runtime.UnlockOSThread()
// 		// 	log.Info("Received signal:", sig)

// 		// 	// Call stop function or perform cleanup
// 		// 	if err := stop(); err != nil {
// 		// 		log.Error("Error stopping the application:", err)
// 		// 	}
// 		// 	log.Info("Application stopped gracefully.")
// 		// }
// 	}
// }

func main() {}

//export cleanup
func cleanup() {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()
	// C.cleanup_signals()
}

func emptyOrErrorC(err error) *C.char {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err == nil {
		return C.CString("")
	}
	log.Error(err.Error())
	return C.CString(err.Error())
}

const pokrovDesktopABIVersion = 2
const pokrovCoreCapabilitiesJSON = `{"schema_version":1,"desktop_abi":2,"event_abi":1,"capabilities":["bounded_stop_reason","core_start_stop","materialized_profile","secure_profile_file","structured_operational_events","typed_lifecycle_events"],"lifecycle_events":["initialization","profile","core_start","tun","routes","dns","egress","recovery","stop"],"operational_events":{"contract":"config/core-event-abi.json","schema_version":1,"event_abi":1,"callback_symbol":"pokrovCoreSetEventCallback","context_symbol":"pokrovCoreSetEventContext","maximum_pending_events":128}}`

//export pokrovCoreAbiVersion
func pokrovCoreAbiVersion() C.int {
	return C.int(pokrovDesktopABIVersion)
}

//export pokrovCoreCapabilities
func pokrovCoreCapabilities() *C.char {
	return C.CString(pokrovCoreCapabilitiesJSON)
}

//export pokrovCoreSetEventCallback
func pokrovCoreSetEventCallback(callback C.pokrov_core_event_callback_v1) {
	if C.pokrov_core_event_callback_is_null(callback) != 0 {
		hcore.SetOperationalEventSink(nil)
		return
	}
	hcore.SetOperationalEventSink(func(event hcore.OperationalEvent) {
		occurredAt := C.CString(event.OccurredAtRFC3339())
		runID := C.CString(event.RunID)
		attemptID := C.CString(event.AttemptID)
		name := C.CString(event.Name)
		subsystem := C.CString(event.Subsystem)
		stage := C.CString(event.Stage)
		severity := C.CString(string(event.Severity))
		outcome := C.CString(string(event.Outcome))
		errorCode := C.CString(event.ErrorCode)
		phase := C.CString(event.Phase)
		defer func() {
			for _, value := range []*C.char{
				occurredAt, runID, attemptID, name, subsystem, stage,
				severity, outcome, errorCode, phase,
			} {
				C.free(unsafe.Pointer(value))
			}
		}()
		C.pokrov_core_emit_event_v1(
			callback,
			C.int(event.SchemaVersion),
			C.int(event.EventABI),
			occurredAt,
			runID,
			attemptID,
			C.longlong(event.Generation),
			C.longlong(event.Sequence),
			name,
			subsystem,
			stage,
			severity,
			outcome,
			errorCode,
			phase,
		)
	})
}

//export pokrovCoreSetEventContext
func pokrovCoreSetEventContext(runID *C.char, attemptID *C.char, generation C.longlong) *C.char {
	return emptyOrErrorC(hcore.ConfigureOperationalEventContext(
		C.GoString(runID),
		C.GoString(attemptID),
		int64(generation),
	))
}

//export pokrovSecureFile
func pokrovSecureFile(path *C.char) *C.char {
	return emptyOrErrorC(hutils.Chmod(C.GoString(path), 0o600))
}

//export setup
func setup(baseDir *C.char, workingDir *C.char, tempDir *C.char, mode C.int, listen *C.char, secret *C.char, statusPort C.longlong, debug bool) *C.char {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	// // Ensure signals are initialized
	// C.init_signals()

	params := hcore.SetupRequest{
		BasePath:          C.GoString(baseDir),
		WorkingDir:        C.GoString(workingDir),
		TempDir:           C.GoString(tempDir),
		FlutterStatusPort: int64(statusPort),
		Debug:             bool(debug),
		Mode:              hcore.SetupMode(mode),
		Listen:            C.GoString(listen),
		Secret:            C.GoString(secret),
	}

	err := hcore.Setup(&params, nil)
	return emptyOrErrorC(err)
}

//export freeString
func freeString(str *C.char) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	C.free(unsafe.Pointer(str))
}

//export start
func start(configPath *C.char, disableMemoryLimit bool) *C.char {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()
	ctx := libbox.BaseContext(nil)
	_, err := hcore.Start(ctx, &hcore.StartRequest{
		ConfigPath:             C.GoString(configPath),
		EnableOldCommandServer: false,
		EnableRawConfig:        true,
		DisableMemoryLimit:     bool(disableMemoryLimit),
	})
	return emptyOrErrorC(err)
}

//export stop
func stop() *C.char {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	_, err := hcore.Stop()
	return emptyOrErrorC(err)
}

//export restart
func restart(configPath *C.char, disableMemoryLimit bool) *C.char {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()
	ctx := libbox.BaseContext(nil)
	_, err := hcore.Restart(ctx, &hcore.StartRequest{
		ConfigPath:             C.GoString(configPath),
		EnableOldCommandServer: false,
		EnableRawConfig:        true,
		DisableMemoryLimit:     bool(disableMemoryLimit),
	})
	return emptyOrErrorC(err)
}

//export GetServerPublicKey
func GetServerPublicKey() *C.char {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	publicKey := hcore.GetGrpcServerPublicKey()
	return C.CString(string(publicKey)) // Return as C string, caller must free
}

//export AddGrpcClientPublicKey
func AddGrpcClientPublicKey(clientPublicKey *C.char) *C.char {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	// Convert C string to Go byte slice
	clientKey := C.GoBytes(unsafe.Pointer(clientPublicKey), C.int(len(C.GoString(clientPublicKey))))
	err := hcore.AddGrpcClientPublicKey(clientKey)
	return emptyOrErrorC(err)
}

//export closeGrpc
func closeGrpc(mode C.int) {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	hcore.Close(hcore.SetupMode(mode))
}
