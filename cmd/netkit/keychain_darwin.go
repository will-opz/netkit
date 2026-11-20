//go:build darwin

package main

import (
 "context"
 "errors"
 "os"
 "os/exec"
 "strings"
 "time"
)

const keychainTool="/usr/bin/security"

// Calls never put a password in argv, a shell script, or logged errors.
// The macOS security CLI is used as the identity for access-control prompts.
func readKeychainSecret(service,account string)(string,error){
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(ctx,keychainTool,"find-generic-password","-s",service,"-a",account,"-w")
 var output strings.Builder
 cmd.Stdout=&output
 if err:=cmd.Run();err!=nil{
  return "",errors.New("Keychain credential unavailable; run 'netkit config ai-key set' or use NETKIT_AI_API_KEY")
 }
 key:=strings.TrimRight(output.String(),"\r\n")
 if key==""{return "",errors.New("Keychain credential is empty")}
 return key,nil
}
func keychainSecretExists(service,account string)(bool,error){
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(ctx,keychainTool,"find-generic-password","-s",service,"-a",account)
 // Never echo metadata or secret bytes.
 err:=cmd.Run()
 if ctx.Err()!=nil{return false,errors.New("Keychain status check timed out")}
 if err==nil{return true,nil}
 var exit *exec.ExitError
 if errors.As(err,&exit)&&exit.ExitCode()==44{return false,nil} // errSecItemNotFound
 return false,errors.New("Keychain status unavailable; check login Keychain access")

}
func storeKeychainSecret(service,account string)error{
 // -w without an argument prompts via the macOS security CLI. Do not
 // add an API key value to args or shell history.
 cmd:=exec.Command(keychainTool,"add-generic-password","-s",service,"-a",account,"-U","-w")
 cmd.Stdin=os.Stdin
 cmd.Stdout=os.Stdout
 cmd.Stderr=os.Stderr
 if err:=cmd.Run();err!=nil{return errors.New("Keychain save failed or was cancelled")}
 return nil
}
func deleteKeychainSecret(service,account string)error{
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(ctx,keychainTool,"delete-generic-password","-s",service,"-a",account)
 if err:=cmd.Run();err!=nil{return errors.New("Keychain delete failed or item not found")}
 return nil
}
