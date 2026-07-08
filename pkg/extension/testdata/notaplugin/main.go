// Command notaplugin is a valid executable that is NOT a go-plugin extension.
// The loader's dialer tests point at it to exercise the handshake-failure path:
// the process launches but never completes the go-plugin handshake, so the host
// must treat it as a failed load and skip it.
package main

func main() {}
