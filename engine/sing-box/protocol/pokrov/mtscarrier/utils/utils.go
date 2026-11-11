package utils

func Debugf(string, ...any)     {}
func SafeGo(_ string, f func()) { go f() }
