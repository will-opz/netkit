package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "strings"
)

// These variables are replaced at build time only for tagged releases.
var version = "dev"
var commit = "unknown"

type VersionInfo struct {
 Version string `json:"version"`
 Commit string `json:"commit"`
}

func runVersion(args []string) error {
 format:="text"
 if len(args)>1{return errors.New("usage: netkit version [--output json]")}
 if len(args)==1{
  switch args[0]{
  case "--output=json","-output=json","--json":format="json"
  default:return fmt.Errorf("unsupported version option: %s",args[0])
  }
 }
 info:=VersionInfo{Version:version,Commit:commit}
 if format=="json"{
  encoded,err:=json.Marshal(info)
  if err!=nil{return err}
  fmt.Println(string(encoded))
  return nil
 }
 fmt.Printf("netkit %s",strings.TrimSpace(info.Version))
 if info.Commit!=""&&info.Commit!="unknown"{fmt.Printf(" (%s)",info.Commit)}
 fmt.Println()
 return nil
}
