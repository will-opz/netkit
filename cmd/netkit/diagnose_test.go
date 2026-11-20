package main

import (
 "context"
 "encoding/json"
 "errors"
 "net"
 "net/http"
 "strings"
 "testing"
 "time"
)

func fixedDiagnosticResolve(_ context.Context,host string)([]net.IPAddr,error){
 return []net.IPAddr{{IP:net.ParseIP("127.0.0.1")}},nil
}
func mockDiagnosticProbes()DiagnosticProbes{
 return DiagnosticProbes{
  Resolve:fixedDiagnosticResolve,
  TCP:func(context.Context,string,int,TCPResolver)TCPReport{
   return TCPReport{Status:"connected",ConnectedIP:"127.0.0.1",Attempts:[]TCPAttempt{{IP:"127.0.0.1",Connected:true}}}
  },
  TLS:func(host string,port int,timeout time.Duration)TLSReport{
   return TLSReport{Host:host,Port:port,Connected:true,Verified:true}
  },
  HTTP:func(context.Context,*http.Client,string,int)HTTPReport{
   return HTTPReport{Status:"ok",Hops:[]HTTPHop{{StatusCode:200,DurationMS:3}}}
  },
 }
}
func TestDiagnoseInputValidation(t *testing.T){
 for _,tc:=range []struct{raw,host,scheme string;port int;steps int}{
  {"example.com","example.com","https",443,4},
  {"example.com:8443","example.com","https",8443,4},
  {"https://example.com/","example.com","https",443,4},
  {"http://example.com","example.com","http",80,3},
  {"http://127.0.0.1:8080/","127.0.0.1","http",8080,3},
  {"https://[::1]:8443","::1","https",8443,4},
  {"localhost","localhost","https",443,4},
 }{
  got,err:=parseDiagnosticTarget(tc.raw)
  if err!=nil||got.Host!=tc.host||got.Port!=tc.port||got.Scheme!=tc.scheme||len(got.Steps)!=tc.steps{
   t.Errorf("%s: %+v, %v",tc.raw,got,err)
  }
 }
 for _,target:=range []string{""," example.com","ftp://example.com","https://user:pass@example.com","https://example.com/secret","https://example.com/?token=1","https://example.com/#frag","example.com:99999","bad host","https://example.com:abc"}{
  if _,err:=parseDiagnosticTarget(target);err==nil{t.Errorf("accepted unsafe/invalid target %q",target)}
 }
}
func TestDiagnoseSuccessfulEvidence(t *testing.T){
 plan,_:=parseDiagnosticTarget("example.com")
 report:=diagnose(context.Background(),plan,time.Second,mockDiagnosticProbes())
 if report.Status!="ok"||report.FirstFailure!=""||len(report.Stages)!=4{t.Fatalf("unexpected: %+v",report)}
 want:=[]string{"dns.1","tcp.1","tls.1","http.1"}
 for i,stage:=range report.Stages{
  if stage.ID!=want[i]||stage.Status!="ok"||stage.Observer!="local_machine"{t.Errorf("bad stage: %+v",stage)}
 }
 if report.SchemaVersion!="1"||report.ObservedAt==""||report.DurationMS<0{t.Fatalf("missing provenance: %+v",report)}
 encoded,err:=json.Marshal(report)
 if err!=nil{t.Fatal(err)}
 if !strings.Contains(string(encoded),"\"schema_version\"")||!strings.Contains(string(encoded),"\"stages\""){t.Fatalf("invalid JSON: %s",encoded)}
}
func TestDiagnoseDNSFailureSkipsLaterStages(t *testing.T){
 plan,_:=parseDiagnosticTarget("example.com")
 p:=mockDiagnosticProbes()
 p.Resolve=func(context.Context,string)([]net.IPAddr,error){return nil,errors.New("NXDOMAIN-like system lookup error")}
 p.TCP=func(context.Context,string,int,TCPResolver)TCPReport{t.Fatal("TCP must not run after DNS fail");return TCPReport{}}
 r:=diagnose(context.Background(),plan,time.Second,p)
 if r.Status!="failed"||r.FirstFailure!="dns.1"||len(r.Stages)!=4{t.Fatalf("bad DNS error: %+v",r)}
 for _,s:=range r.Stages[1:]{if s.Status!="skipped"{t.Errorf("not skipped: %+v",s)}}
}
func TestDiagnoseTCPFailureSkipsTLSHTTP(t *testing.T){
 plan,_:=parseDiagnosticTarget("example.com")
 p:=mockDiagnosticProbes()
 p.TCP=func(context.Context,string,int,TCPResolver)TCPReport{return TCPReport{Status:"connect_error"}}
 p.TLS=func(string,int,time.Duration)TLSReport{t.Fatal("TLS must not run");return TLSReport{}}
 r:=diagnose(context.Background(),plan,time.Second,p)
 if r.FirstFailure!="tcp.1"||r.Stages[2].Status!="skipped"||r.Stages[3].Status!="skipped"{t.Fatalf("bad TCP failure: %+v",r)}
}
func TestDiagnoseTLSFailureSkipsHTTP(t *testing.T){
 plan,_:=parseDiagnosticTarget("example.com")
 p:=mockDiagnosticProbes()
 p.TLS=func(string,int,time.Duration)TLSReport{return TLSReport{Connected:true,Verified:false,VerificationCode:"hostname_mismatch"}}
 p.HTTP=func(context.Context,*http.Client,string,int)HTTPReport{t.Fatal("HTTP must not run when TLS invalid");return HTTPReport{}}
 r:=diagnose(context.Background(),plan,time.Second,p)
 if r.FirstFailure!="tls.1"||r.Stages[2].Error!="hostname_mismatch"||r.Stages[3].Status!="skipped"{t.Fatalf("bad TLS report: %+v",r)}
}
func TestDiagnoseHTTPRestricted(t *testing.T){
 plan,_:=parseDiagnosticTarget("http://example.com")
 p:=mockDiagnosticProbes()
 p.TLS=func(string,int,time.Duration)TLSReport{t.Fatal("HTTP must skip TLS");return TLSReport{}}
 p.HTTP=func(context.Context,*http.Client,string,int)HTTPReport{return HTTPReport{Status:"restricted",Hops:[]HTTPHop{{StatusCode:403}}}}
 r:=diagnose(context.Background(),plan,time.Second,p)
 if r.Status!="degraded"||len(r.Stages)!=3||r.FirstFailure!=""||r.Stages[2].Status!="restricted"{t.Fatalf("restricted: %+v",r)}
}
func TestDiagnoseHTTPErrors(t *testing.T){
 plan,_:=parseDiagnosticTarget("http://example.com")
 p:=mockDiagnosticProbes()
 p.HTTP=func(context.Context,*http.Client,string,int)HTTPReport{return HTTPReport{Status:"http_error",Hops:[]HTTPHop{{StatusCode:503}}}}
 r:=diagnose(context.Background(),plan,time.Second,p)
 if r.Status!="failed"||r.FirstFailure!="http.1"{t.Fatalf("bad HTTP failure: %+v",r)}
}
func TestDiagnoseReusesDNSAddressSet(t *testing.T){
 plan,_:=parseDiagnosticTarget("example.com")
 p:=mockDiagnosticProbes()
 p.TCP=func(ctx context.Context,host string,port int,resolve TCPResolver)TCPReport{
  addresses,err:=resolve(ctx,host)
  if err!=nil||len(addresses)!=1||addresses[0].IP.String()!="127.0.0.1"{t.Fatalf("not same DNS evidence: %v %v",addresses,err)}
  return TCPReport{Status:"connected"}
 }
 report:=diagnose(context.Background(),plan,time.Second,p)
 if report.Status!="ok"{t.Fatalf("unexpected: %+v",report)}
}
