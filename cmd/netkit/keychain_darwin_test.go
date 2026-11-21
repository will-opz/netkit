//go:build darwin

package main

import (
 "errors"
 "strconv"
 "strings"
 "testing"
)

func TestKeychainLongSecretRoundTrip(t *testing.T){
 // Old `security ... -w` prompt can truncate this valid-length token.
 token:="sk-proj-"+strings.Repeat("A",156) // 164 bytes
 if len(token)!=164{t.Fatal("fixture length")}
 called:=0
 err:=storeKeychainSecretChecked("netkit.ai","openai",token,
  func(command string)error{
   called++
   if !strings.HasPrefix(command,"add-generic-password -U -a "){t.Fatal("wrong batch command")}
   if !strings.Contains(command," -w "){t.Fatal("missing password argument in stdin batch")}
   if !strings.Contains(command,token){t.Fatal("command was truncated")}
   if strings.Count(command,"\n")!=1{t.Fatal("batch must be one line")}
   return nil
  },
  func(service,account string)(string,error){
   if service!="netkit.ai"||account!="openai"{t.Fatalf("incorrect item: %s/%s",service,account)}
   return token,nil
  })
 if err!=nil||called!=1{t.Fatalf("long token not verified: %v",err)}
}
func TestKeychainRefusesTruncationAndMissingReadback(t *testing.T){
 token:="sk-proj-"+strings.Repeat("A",156)
 for _,tc:=range []struct{name string;read func(string,string)(string,error)}{
  {"truncated",func(string,string)(string,error){return token[:128],nil}},
  {"access_denied",func(string,string)(string,error){return "",errors.New("secret-details")}},
 }{
  t.Run(tc.name,func(t *testing.T){
   err:=storeKeychainSecretChecked("netkit.ai","openai",token,
    func(string)error{return nil},tc.read)
   if err==nil{t.Fatal("unverified save reported success")}
   if strings.Contains(err.Error(),"secret-details"){t.Fatal("secret-bearing error leaked")}
  })
 }
}
func TestSecurityBatchCannotInjectExtraCommands(t *testing.T){
 for _,secret:=range []string{"","a\nb","ab\rc","abc def","a\tb","a\x00b"}{
  if _,err:=securityBatchCommand("netkit.ai","openai",secret);err==nil{
   t.Errorf("accepted unsafe secret %q",secret)
  }
 }
 secret:=`sk-proj-a"\\b`
 cmd,err:=securityBatchCommand("netkit.ai","openai",secret)
 if err!=nil{t.Fatal(err)}
 if strings.Count(cmd,"\n")!=1||!strings.Contains(cmd,strconv.Quote(secret)){
  t.Errorf("unsafe quoting: %q",cmd)
 }
}
