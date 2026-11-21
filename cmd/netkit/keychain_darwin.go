//go:build darwin

package main

import (
 "bufio"
 "bytes"
 "context"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "strconv"
 "strings"
 "time"
)

const keychainTool="/usr/bin/security"

// macOS security's bare -w prompt may truncate secrets around 128 chars.
// Read the full line ourselves, then submit a quoted command over stdin to
// security -i. The secret never appears in process arguments or shell history.
// Neither terminal echoes nor security's stdout/stderr may reveal the secret.
func readSecretFromTerminal()(string,error){
 stty:=func(args ...string)error{
  cmd:=exec.Command("/bin/stty",args...)
  cmd.Stdin=os.Stdin
  cmd.Stdout=io.Discard
  cmd.Stderr=io.Discard
  return cmd.Run()
 }
 if err:=stty("-echo");err!=nil{
  return "",errors.New("an interactive terminal is required to set the API key")
 }
 defer stty("echo")
 fmt.Fprint(os.Stderr,"Paste API key (hidden; press Enter): ")
 line,err:=bufio.NewReader(os.Stdin).ReadString('\n')
 fmt.Fprintln(os.Stderr)
 if err!=nil{return "",errors.New("could not read complete API key from terminal")}
 key:=strings.TrimSuffix(strings.TrimSuffix(line,"\n"),"\r")
 if err:=validateKeychainInput(key);err!=nil{return "",err}
 return key,nil
}
func validateKeychainInput(key string)error{
 if len(key)==0||len(key)>16384{return errors.New("API key must be between 1 and 16384 bytes")}
 // security -i is a line-oriented command interpreter, and secrets
 // containing control characters cannot safely be represented in its input.
 for _,r:=range key{
  if r<33||r>126{return errors.New("API key must contain printable ASCII without whitespace")}
 }
 return nil
}
func securityBatchCommand(service,account,key string)(string,error){
 if err:=validateKeychainInput(key);err!=nil{return "",err}
 // Quoting is required: never allow user input to become another command.
 quote:=func(s string)string{return strconv.Quote(s)}
 return "add-generic-password -U -a "+quote(account)+" -s "+quote(service)+" -w "+quote(key)+"\n",nil
}
func securityBatchStore(command string)error{
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(ctx,keychainTool,"-i")
 cmd.Stdin=bytes.NewBufferString(command)
 cmd.Stdout=io.Discard
 cmd.Stderr=io.Discard
 if err:=cmd.Run();err!=nil{
  return errors.New("Keychain save failed or was denied")
 }
 return nil
}
func storeKeychainSecretChecked(service,account,key string,store func(string)error,read func(string,string)(string,error))error{
 command,err:=securityBatchCommand(service,account,key)
 if err!=nil{return err}
 if err:=store(command);err!=nil{return err}
 saved,err:=read(service,account)
 if err!=nil{return errors.New("Keychain saved item could not be verified; check access permissions")}
 if saved!=key{
  return errors.New("Keychain verification failed: saved secret differs from input (possible truncation); do not use this credential")
 }
 return nil
}

func readKeychainSecret(service,account string)(string,error){
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(ctx,keychainTool,"find-generic-password","-s",service,"-a",account,"-w")
 var output strings.Builder
 cmd.Stdout=&output
 cmd.Stderr=io.Discard
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
 err:=cmd.Run()
 if ctx.Err()!=nil{return false,errors.New("Keychain status check timed out")}
 if err==nil{return true,nil}
 var exit *exec.ExitError
 if errors.As(err,&exit)&&exit.ExitCode()==44{return false,nil}
 return false,errors.New("Keychain status unavailable; check login Keychain access")
}
func storeKeychainSecret(service,account string)error{
 key,err:=readSecretFromTerminal()
 if err!=nil{return err}
 return storeKeychainSecretChecked(service,account,key,securityBatchStore,readKeychainSecret)
}
func deleteKeychainSecret(service,account string)error{
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(ctx,keychainTool,"delete-generic-password","-s",service,"-a",account)
 if err:=cmd.Run();err!=nil{return errors.New("Keychain delete failed or item not found")}
 return nil
}
