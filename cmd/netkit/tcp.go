package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "strconv"
 "strings"
 "time"
)

// TCPAttempt is an observation from this machine, not a remote probe.
type TCPAttempt struct {
 IP string `json:"ip"`
 Address string `json:"address"`
 Family string `json:"family"`
 Connected bool `json:"connected"`
 DurationMS int64 `json:"duration_ms"`
 Error string `json:"error,omitempty"`
}
type TCPReport struct {
 Host string `json:"host"`
 Port int `json:"port"`
 Status string `json:"status"`
 ResolvedIPs []string `json:"resolved_ips,omitempty"`
 DNSDurationMS int64 `json:"dns_duration_ms"`
 DNSerror string `json:"dns_error,omitempty"`
 Attempts []TCPAttempt `json:"attempts"`
 AllIPs bool `json:"all_ips,omitempty"`
 SuccessCount int `json:"success_count,omitempty"`
 FailureCount int `json:"failure_count,omitempty"`
 ConnectedIP string `json:"connected_ip,omitempty"`
 ConnectDurationMS int64 `json:"connect_duration_ms,omitempty"`
 TotalDurationMS int64 `json:"total_duration_ms"`
}

// TCPResolver allows a deterministic local test without external DNS requests.
type TCPResolver func(context.Context,string)([]net.IPAddr,error)
func systemTCPResolve(ctx context.Context,name string)([]net.IPAddr,error){
 return net.DefaultResolver.LookupIPAddr(ctx,name)
}
func validTCPHost(host string)bool{
 if host==""||strings.TrimSpace(host)!=host||strings.ContainsAny(host,"/@\\ \t\r\n"){return false}
 if net.ParseIP(host)!=nil{return true}
 if strings.EqualFold(host,"localhost"){return true}
 return validDomain(host)
}
func probeTCP(ctx context.Context,host string,port int,resolve TCPResolver)(report TCPReport){
 return probeTCPMode(ctx,host,port,resolve,false)
}
type TCPDial func(context.Context,string,string)(net.Conn,error)
func probeTCPMode(ctx context.Context,host string,port int,resolve TCPResolver,allIPs bool)(report TCPReport){
 return probeTCPWithDial(ctx,host,port,resolve,allIPs,(&net.Dialer{}).DialContext)
}
func probeTCPWithDial(ctx context.Context,host string,port int,resolve TCPResolver,allIPs bool,dial TCPDial)(report TCPReport){
 report=TCPReport{Host:host,Port:port,Status:"unknown",Attempts:[]TCPAttempt{},AllIPs:allIPs}
 start:=time.Now()
 defer func(){report.TotalDurationMS=time.Since(start).Milliseconds()}()
 if resolve==nil {resolve=systemTCPResolve}
 var addresses []net.IPAddr
 if ip:=net.ParseIP(host);ip!=nil{
  addresses=[]net.IPAddr{{IP:ip}}
 }else{
  started:=time.Now()
  var err error
  addresses,err=resolve(ctx,host)
  report.DNSDurationMS=time.Since(started).Milliseconds()
  if err!=nil{
   report.DNSerror=err.Error()
   report.Status="dns_error"
   if ctx.Err()!=nil{report.Status="timeout"}
   return report
  }
 }
 seen:=map[string]bool{}
 for _,address:=range addresses{
  if address.IP==nil{continue}
  ip:=address.IP.String()
  if seen[ip]{continue}
  seen[ip]=true
  report.ResolvedIPs=append(report.ResolvedIPs,ip)
 }
 if len(report.ResolvedIPs)==0{
  report.Status="dns_error"
  report.DNSerror="no usable IP addresses"
  return report
 }
 for _,ip:=range report.ResolvedIPs{
  family:="IPv6"
  if net.ParseIP(ip).To4()!=nil{family="IPv4"}
  addr:=net.JoinHostPort(ip,fmt.Sprint(port))
  started:=time.Now()
  conn,err:=dial(ctx,"tcp",addr)
  duration:=time.Since(started).Milliseconds()
  attempt:=TCPAttempt{IP:ip,Address:addr,Family:family,DurationMS:duration}
  if err==nil{
   attempt.Connected=true
   conn.Close()
   report.Attempts=append(report.Attempts,attempt)
   if report.ConnectedIP==""{
    report.ConnectedIP=ip
    report.ConnectDurationMS=duration
   }
   report.SuccessCount++
   report.Status="connected"
   if !allIPs{return report}
   continue
  }
  attempt.Error=err.Error()
  report.Attempts=append(report.Attempts,attempt)
  report.FailureCount++
  if ctx.Err()!=nil{
   report.Status="timeout"
   return report
  }
 }
 if allIPs&&report.SuccessCount>0{
  if report.FailureCount>0{report.Status="partial_failure"
  }else{report.Status="connected"}
 }else{report.Status="connect_error"}
 return report
}
func tcpHelp(){
 fmt.Println("用法: netkit tcp [-timeout 5s] [-all-ips] [--output text|json] [-lang zh|en] HOST PORT")
 fmt.Println("示例: netkit tcp example.com 443")
 fmt.Println("      netkit tcp -timeout 3s --output json 127.0.0.1 5432")
 fmt.Println("      netkit tcp -all-ips example.com 443")
 fmt.Println("仅尝试 TCP 连接，不执行 TLS 握手或 HTTP 请求；检测位置为运行本命令的机器")
}
func runTCP(args []string)error{
 if len(args)==0||args[0]=="-h"||args[0]=="--help"{tcpHelp();return nil}
 fs:=flag.NewFlagSet("tcp",flag.ContinueOnError)
 timeout:=fs.Duration("timeout",5*time.Second,"total DNS + TCP timeout")
 allIPs:=fs.Bool("all-ips",false,"probe every resolved IP within the overall timeout")
 output:=fs.String("output","text","text or json")
 lang:=fs.String("lang","zh","zh or en")
 if err:=fs.Parse(args);err!=nil{return err}
 if *timeout<=0{return errors.New("-timeout must be positive")}
 if *lang!="zh"&&*lang!="en"{return errors.New("-lang must be zh or en")}
 format,err:=resolveOutputFormat(*output,false)
 if err!=nil{return err}
 if fs.NArg()!=2||!validTCPHost(fs.Arg(0)){return errors.New("expected HOST PORT (valid hostname or IPv4/IPv6 address)")}
 port,err:=strconv.Atoi(fs.Arg(1))
 if err!=nil||port<1||port>65535{return errors.New("PORT must be a numeric TCP port (1-65535)")}
 host:=strings.TrimSuffix(fs.Arg(0),".")
 ctx,cancel:=context.WithTimeout(context.Background(),*timeout)
 defer cancel()
 r:=probeTCPMode(ctx,host,port,nil,*allIPs)
 if format=="json"{
  b,err:=json.MarshalIndent(r,"","  ");if err!=nil{return err}
  fmt.Println(string(b))
 }else{
  name:=func(zh,en string)string{if *lang=="en"{return en};return zh}
  fmt.Printf("%s: %s\n",name("TCP 目标","TCP target"),net.JoinHostPort(host,fmt.Sprint(port)))
  if r.DNSerror!=""{
   fmt.Printf("  DNS: %s\n",r.DNSerror)
  }else{
   fmt.Printf("  DNS: %s (%dms)\n",strings.Join(r.ResolvedIPs,", "),r.DNSDurationMS)
  }
  for _,attempt:=range r.Attempts{
   state:=name("连接失败","Failed")
   if attempt.Connected{state=name("连接成功","Connected")}
   fmt.Printf("  %s | %s | %s | %dms\n",attempt.Address,attempt.Family,state,attempt.DurationMS)
   if attempt.Error!=""{fmt.Printf("    %s: %s\n",name("原因","Reason"),attempt.Error)}
  }
  fmt.Printf("%s: %s | %s: %dms\n",name("结果","Result"),r.Status,name("总耗时","Total"),r.TotalDurationMS)
  if r.AllIPs{fmt.Printf("  %s: %d | %s: %d\n",name("成功","Success"),r.SuccessCount,name("失败","Failed"),r.FailureCount)}
 }
 if r.Status!="connected"{return fmt.Errorf("TCP diagnostic: %s",r.Status)}
 return nil
}
