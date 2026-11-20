//go:build !darwin

package main

import "errors"

var errKeychainUnsupported=errors.New("macOS Keychain is unavailable on this platform; use NETKIT_AI_API_KEY")

func readKeychainSecret(service,account string)(string,error){return "",errKeychainUnsupported}
func keychainSecretExists(service,account string)(bool,error){return false,errKeychainUnsupported}
func storeKeychainSecret(service,account string)error{return errKeychainUnsupported}
func deleteKeychainSecret(service,account string)error{return errKeychainUnsupported}
