package main

import (
 "encoding/json"
 "testing"
)

func TestVersionMetadataDefaults(t *testing.T){
 if version==""||commit==""{
  t.Fatal("build metadata must have nonempty defaults")
 }
 info:=VersionInfo{Version:"v0.9.0",Commit:"abcdef123456"}
 encoded,err:=json.Marshal(info)
 if err!=nil{t.Fatal(err)}
 var decoded map[string]string
 if err:=json.Unmarshal(encoded,&decoded);err!=nil{t.Fatal(err)}
 if decoded["version"]!=info.Version||decoded["commit"]!=info.Commit{
  t.Fatalf("incorrect version contract: %s",encoded)
 }
}
func TestVersionCLIModeValidation(t *testing.T){
 for _,args:=range [][]string{{"unexpected"},{"--output=json","extra"}}{
  if err:=runVersion(args);err==nil{t.Errorf("expected version arguments to be rejected: %v",args)}
 }
}
