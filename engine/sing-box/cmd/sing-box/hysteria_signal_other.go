//go:build !linux

package main

import "os"

func hysteriaReloadSignal() os.Signal { return nil }
