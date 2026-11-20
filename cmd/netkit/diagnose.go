package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "net/http"
 "net/url"
 "strconv"
 "strings"
 "time"
)

// EvidenceBundle is intentionally independent of an AI provider. Every stage
// includes its source and the stable ID to which future AI output may refer.
type DiagnosticStage struct {
 ID string `json:"id"`
 Layer string `json:"layer"`
 Status string `json:"status"`
 Observer string `json:"observer"`
 DurationMS int64 `json:"duration_ms"`
 Error string `json:"error,omitempty"`
 DNS *DiagnosticDNS `json:"dns,omitempty"`
 TCP *TCPReport `json:"tcp,omitempty"`
 TLS *TLSReport `json:"tls,omitempty"`
 HTTP *HTTPReport `json:"http,omitempty"`
}
type DiagnosticDNS struct {
 Host string `json:"host"`
 IPs []string `json:"ips"`
 // The system resolver API does not expose RCODE or TTL.
}
type DiagnosticPlan struct {
 Target string `json:"target"`
 Host string `json:"host"`
 Port int `json:"port"`
 Scheme string `json:"scheme"`
 Steps []string `json:"steps"`
}
type EvidenceBundle struct {
 SchemaVersion string `json:"schema_version"`
 Plan DiagnosticPlan `json:"plan"`
 ObservedAt string `json:"observed_at"`
 Observer string `json:"observer"`
 Status string `json:"status"`
 FirstFailure string `json:"first_failure,omitempty"`
 Stages []DiagnosticStage `json:"stages"`
 DurationMS int64 `json:"duration_ms"`
 AIAnalysis *AIAnalysis `json:"ai_analysis,omitempty"`
 AIError string `json:"ai_error,omitempty"`
}
type DiagnosticResolve func(context.Context,string)([]net.IPAddr,error)
type DiagnosticProbes struct {
 Resolve DiagnosticResolve
 TCP func(context.Context,string,int,TCPResolver)TCPReport
 TLS func(string,int,time.Duration)TLSReport
 HTTP func(context.Context,*http.Client,string,int)HTTPReport
}

func defaultDiagnosticProbes()DiagnosticProbes {
 return DiagnosticProbes{
  Resolve:net.DefaultResolver.LookupIPAddr,
  TCP:probeTCP,
  TLS:inspectTLS,
  HTTP:traceHTTP,
 }
}
func parseDiagnosticTarget(raw string)(DiagnosticPlan,error){
 var p DiagnosticPlan
 if strings.TrimSpace(raw)!=raw||raw==""{return p,errors.New("expected a single hostname, IP or HTTP(S) URL")}
 target:=raw
 if !strings.Contains(raw,"://"){target="https://"+raw}
 u,err:=url.Parse(target)
 if err!=nil{return p,err}
 if (u.Scheme!="http"&&u.Scheme!="https")||u.User!=nil||u.Hostname()==""||u.Fragment!=""||u.Opaque!=""{
  return p,errors.New("expected a valid HTTP(S) URL or host without credentials/fragments")
 }
 if u.Path!=""&&u.Path!="/"||u.RawQuery!=""{
  return p,errors.New("diagnose accepts a host/URL root only; use netkit http for paths and queries")
 }
 host:=strings.TrimSuffix(strings.ToLower(u.Hostname()),".")
 if !validTCPHost(host){return p,fmt.Errorf("invalid diagnostic host %q",host)}
 port:=443
 if u.Scheme=="http"{port=80}
 if u.Port()!=""{
  port,err=strconv.Atoi(u.Port())
  if err!=nil||port<1||port>65535{return p,errors.New("port must be 1-65535")}
 }
 p=DiagnosticPlan{Target:raw,Host:host,Port:port,Scheme:u.Scheme,Steps:[]string{"dns","tcp"}}
 if u.Scheme=="https"{p.Steps=append(p.Steps,"tls")}
 p.Steps=append(p.Steps,"http")
 return p,nil
}
func skippedStage(layer,reason string)DiagnosticStage{
 return DiagnosticStage{ID:layer+".1",Layer:layer,Observer:"local_machine",Status:"skipped",Error:reason}
}
func diagnose(ctx context.Context,plan DiagnosticPlan,perStage time.Duration,probes DiagnosticProbes)(bundle EvidenceBundle){
 started:=time.Now()
 bundle=EvidenceBundle{
  SchemaVersion:"1",Plan:plan,ObservedAt:started.UTC().Format(time.RFC3339),
  Observer:"local_machine",Status:"ok",Stages:[]DiagnosticStage{},
 }
 defer func(){bundle.DurationMS=time.Since(started).Milliseconds()}()
 // Failures do not become unsupported guesses: the first confirmed failing
 // layer is retained, and downstream probes are explicitly marked skipped.
 add:=func(stage DiagnosticStage){
  bundle.Stages=append(bundle.Stages,stage)
  if stage.Status=="failed"{
   if bundle.FirstFailure==""{bundle.FirstFailure=stage.ID}
   bundle.Status="failed"
  }else if stage.Status=="restricted"&&bundle.Status=="ok"{bundle.Status="degraded"}
 }
 dnsStage:=DiagnosticStage{ID:"dns.1",Layer:"dns",Observer:"local_machine",Status:"ok"}
 dnsStart:=time.Now()
 dnsCtx,cancel:=context.WithTimeout(ctx,perStage)
 ips,err:=probes.Resolve(dnsCtx,plan.Host)
 cancel()
 dnsStage.DurationMS=time.Since(dnsStart).Milliseconds()
 addresses:=make([]net.IPAddr,0,len(ips))
 stringsIPs:=[]string{}
 seen:=map[string]bool{}
 if err==nil{
  for _,addr:=range ips{
   if addr.IP==nil||seen[addr.IP.String()]{continue}
   seen[addr.IP.String()]=true
   stringsIPs=append(stringsIPs,addr.IP.String())
   addresses=append(addresses,addr)
  }
  if len(addresses)==0{err=errors.New("no usable IP addresses")}
 }
 dnsStage.DNS=&DiagnosticDNS{Host:plan.Host,IPs:stringsIPs}
 if err!=nil{dnsStage.Status="failed";dnsStage.Error=err.Error()}
 add(dnsStage)
 if dnsStage.Status!="ok"{
  for _,layer:=range plan.Steps[1:]{add(skippedStage(layer,"DNS resolution failed"))}
  return bundle
 }
 if ctx.Err()!=nil{
  add(DiagnosticStage{ID:"tcp.1",Layer:"tcp",Observer:"local_machine",Status:"failed",Error:ctx.Err().Error()})
  for _,layer:=range plan.Steps[2:]{add(skippedStage(layer,"overall timeout exceeded"))}
  return bundle
 }
 // Reuse the DNS evidence for TCP to avoid resolving a different address set.
 fixedResolve:=func(context.Context,string)([]net.IPAddr,error){return addresses,nil}
 tcpCtx,stopTCP:=context.WithTimeout(ctx,perStage)
 tcpResult:=probes.TCP(tcpCtx,plan.Host,plan.Port,fixedResolve)
 stopTCP()
 tcpStage:=DiagnosticStage{ID:"tcp.1",Layer:"tcp",Observer:"local_machine",Status:"ok",DurationMS:tcpResult.TotalDurationMS,TCP:&tcpResult}
 if tcpResult.Status!="connected"{tcpStage.Status="failed";tcpStage.Error=tcpResult.Status}
 add(tcpStage)
 if tcpStage.Status!="ok"{
  for _,layer:=range plan.Steps[2:]{add(skippedStage(layer,"TCP connectivity failed"))}
  return bundle
 }
 if plan.Scheme=="https"{
  tlsTimeout:=perStage
  if deadline,ok:=ctx.Deadline();ok{
   remaining:=time.Until(deadline)
   if remaining<tlsTimeout{tlsTimeout=remaining}
  }
  if tlsTimeout<=0{
   add(DiagnosticStage{ID:"tls.1",Layer:"tls",Observer:"local_machine",Status:"failed",Error:"overall timeout exceeded"})
   add(skippedStage("http","overall timeout exceeded"))
   return bundle
  }
  tlsResult:=probes.TLS(plan.Host,plan.Port,tlsTimeout)
  stage:=DiagnosticStage{ID:"tls.1",Layer:"tls",Observer:"local_machine",Status:"ok",DurationMS:tlsResult.DurationMS,TLS:&tlsResult}
  if !tlsResult.Connected||!tlsResult.Verified{
   stage.Status="failed"
   stage.Error=tlsResult.VerificationCode
   if stage.Error==""{stage.Error=tlsResult.ConnectionCode}
   if stage.Error==""{stage.Error="tls_unverified"}
  }
  add(stage)
  if stage.Status!="ok"{add(skippedStage("http","TLS verification failed"));return bundle}
 }
 if ctx.Err()!=nil{
  add(DiagnosticStage{ID:"http.1",Layer:"http",Observer:"local_machine",Status:"failed",Error:ctx.Err().Error()})
  return bundle
 }
 httpCtx,cancelHTTP:=context.WithTimeout(ctx,6*perStage)
 defer cancelHTTP()
 urlTarget:=url.URL{Scheme:plan.Scheme,Host:net.JoinHostPort(plan.Host,strconv.Itoa(plan.Port)),Path:"/"}
 httpStarted:=time.Now()
 httpResult:=probes.HTTP(httpCtx,&http.Client{Timeout:perStage},urlTarget.String(),5)
 stage:=DiagnosticStage{ID:"http.1",Layer:"http",Observer:"local_machine",Status:"ok",HTTP:&httpResult,DurationMS:time.Since(httpStarted).Milliseconds()}
 if httpResult.Status=="restricted"{stage.Status="restricted"}
 if httpResult.Status!="ok"&&httpResult.Status!="restricted"{
  stage.Status="failed"
  stage.Error=httpResult.Status
 }
 add(stage)
 return bundle
}
func diagnoseHelp(){
 fmt.Println("用法: netkit diagnose [-timeout 5s] [-ai] [-ai-allow-private] [--output text|json] [-lang zh|en] HOST|URL")
 fmt.Println("示例: netkit diagnose example.com")
 fmt.Println("      netkit diagnose --output json https://example.com")
 fmt.Println("默认只进行本机 DNS → TCP → TLS(HTTPS) → HTTP；-ai 可选接入 OpenAI-compatible API")
}
func runDiagnose(args []string)error{
 if len(args)==0||args[0]=="-h"||args[0]=="--help"{diagnoseHelp();return nil}
 fs:=flag.NewFlagSet("diagnose",flag.ContinueOnError)
 timeout:=fs.Duration("timeout",5*time.Second,"per-stage timeout")
 output:=fs.String("output","text","text or json")
 lang:=fs.String("lang","zh","zh or en")
 ai:=fs.Bool("ai",false,"optional AI analysis via OpenAI-compatible Chat Completions")
 allowPrivate:=fs.Bool("ai-allow-private",false,"explicitly permit sending private/internal target evidence to AI")
 if err:=fs.Parse(args);err!=nil{return err}
 if fs.NArg()!=1{return errors.New("expected one HOST or URL")}
 if *timeout<=0||*timeout>60*time.Second{return errors.New("-timeout must be between 1ns and 60s")}
 if *lang!="zh"&&*lang!="en"{return errors.New("-lang must be zh or en")}
 format,err:=resolveOutputFormat(*output,false)
 if err!=nil{return err}
 plan,err:=parseDiagnosticTarget(fs.Arg(0))
 if err!=nil{return err}
 ctx,cancel:=context.WithTimeout(context.Background(),10*(*timeout))
 defer cancel()
 result:=diagnose(ctx,plan,*timeout,defaultDiagnosticProbes())
 if *ai{
  settings:=settingsFromEnvironment()
  settings.AllowPrivate=*allowPrivate
  analysis,err:=analyzeWithAI(context.Background(),result,settings,nil)
  if err!=nil{result.AIError=err.Error()}else{result.AIAnalysis=analysis}
 }
 if format=="json"{
  b,err:=json.MarshalIndent(result,"","  ")
  if err!=nil{return err}
  fmt.Println(string(b))
 }else{
  zh:=*lang=="zh"
  if zh{fmt.Printf("综合诊断: %s\n",plan.Target)
  }else{fmt.Printf("Diagnostic: %s\n",plan.Target)}
  for _,stage:=range result.Stages{
   fmt.Printf("  %-8s %-12s %dms  [%s]",strings.ToUpper(stage.Layer),stage.Status,stage.DurationMS,stage.ID)
   if stage.Error!=""{fmt.Printf("  %s",stage.Error)}
   fmt.Println()
  }
  if zh{fmt.Printf("结果: %s",result.Status)
  }else{fmt.Printf("Result: %s",result.Status)}
  if result.FirstFailure!=""{fmt.Printf(" | First failure: %s",result.FirstFailure)}
  fmt.Println()
  if result.AIAnalysis!=nil{
   fmt.Printf("AI [%s]: %s\n",result.AIAnalysis.Model,result.AIAnalysis.Summary)
   for _,check:=range result.AIAnalysis.NextChecks{fmt.Printf("  - %s\n",check)}
  }
  if result.AIError!=""{fmt.Printf("AI unavailable: %s\n",result.AIError)}
 }
 if result.Status=="failed"{return fmt.Errorf("diagnose: %s",result.FirstFailure)}
 return nil
}
