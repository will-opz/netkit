package main

import (
 "crypto/tls"
 "crypto/x509"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "os"
 "strings"
 "time"
)

type TLSReport struct {
 Host string `json:"host"`
 Port int `json:"port"`
 Connected bool `json:"connected"`
 Verified bool `json:"verified"`
 TLSVersion string `json:"tls_version,omitempty"`
 CipherSuite string `json:"cipher_suite,omitempty"`
 ALPN string `json:"alpn,omitempty"`
 Subject string `json:"subject,omitempty"`
 Issuer string `json:"issuer,omitempty"`
 DNSNames []string `json:"dns_names,omitempty"`
 IPAddresses []string `json:"ip_addresses,omitempty"`
 NotBefore string `json:"not_before,omitempty"`
 NotAfter string `json:"not_after,omitempty"`
 DaysRemaining int `json:"days_remaining"`
 ChainLength int `json:"chain_length,omitempty"`
 DurationMS int64 `json:"duration_ms"`
 VerificationError string `json:"verification_error,omitempty"`
 ConnectionError string `json:"connection_error,omitempty"`
}

func tlsVersionName(version uint16)string{
 switch version {
 case tls.VersionTLS10:return "TLS 1.0"
 case tls.VersionTLS11:return "TLS 1.1"
 case tls.VersionTLS12:return "TLS 1.2"
 case tls.VersionTLS13:return "TLS 1.3"
 default:return fmt.Sprintf("0x%x",version)
 }
}

// A diagnostic-only handshake collects the peer certificate even when it is
// expired or untrusted. No application data is sent. The certificate is then
// verified explicitly with system trust roots, correct hostname and intermediates.
func inspectTLS(host string,port int,timeout time.Duration)TLSReport{
 report:=TLSReport{Host:host,Port:port}
 started:=time.Now()
 defer func(){report.DurationMS=time.Since(started).Milliseconds()}()
 address:=net.JoinHostPort(host,fmt.Sprint(port))
 dialer:=&net.Dialer{Timeout:timeout}
 connection,err:=tls.DialWithDialer(dialer,"tcp",address,&tls.Config{
  ServerName:host,
  InsecureSkipVerify:true, // Intentional diagnostics; x509.Verify below.
  MinVersion:tls.VersionTLS10,
 })
 if err!=nil{report.ConnectionError=err.Error();return report}
 defer connection.Close()
 state:=connection.ConnectionState()
 report.Connected=true
 report.TLSVersion=tlsVersionName(state.Version)
 report.CipherSuite=tls.CipherSuiteName(state.CipherSuite)
 report.ALPN=state.NegotiatedProtocol
 report.ChainLength=len(state.PeerCertificates)
 if len(state.PeerCertificates)==0{
  report.VerificationError="no peer certificate"
  return report
 }
 leaf:=state.PeerCertificates[0]
 report.Subject=leaf.Subject.String()
 report.Issuer=leaf.Issuer.String()
 report.DNSNames=append([]string{},leaf.DNSNames...)
 for _,ip:=range leaf.IPAddresses {report.IPAddresses=append(report.IPAddresses,ip.String())}
 report.NotBefore=leaf.NotBefore.UTC().Format(time.RFC3339)
 report.NotAfter=leaf.NotAfter.UTC().Format(time.RFC3339)
 report.DaysRemaining=int(time.Until(leaf.NotAfter).Hours()/24)
 roots,err:=x509.SystemCertPool()
 if err!=nil{
  report.VerificationError="system trust store: "+err.Error()
  return report
 }
 if roots==nil {roots=x509.NewCertPool()}
 intermediates:=x509.NewCertPool()
 for _,cert:=range state.PeerCertificates[1:]{intermediates.AddCert(cert)}
 _,err=leaf.Verify(x509.VerifyOptions{
  DNSName:host,
  Roots:roots,
  Intermediates:intermediates,
  CurrentTime:time.Now(),
  KeyUsages:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
 })
 if err!=nil {report.VerificationError=err.Error();return report}
 report.Verified=true
 return report
}

func validTLSTarget(host string)bool{
 if host==""||strings.ContainsAny(host,"/@\\ \t\n"){return false}
 if net.ParseIP(host)!=nil {return true}
 return validDomain(host)
}
func tlsHelp(){
 fmt.Println("用法: netkit tls [-port 443] [-timeout 5s] [--output text|json] [-lang zh|en] HOST")
 fmt.Println("示例: netkit tls example.com")
 fmt.Println("      netkit tls -port 8443 --output json example.com")
 fmt.Println("说明: 分别报告 TLS 握手与系统信任链/主机名验证结果，不绕过验证结论")
}
func runTLS(args []string)error{
 if len(args)==0||args[0]=="-h"||args[0]=="--help"{tlsHelp();return nil}
 fs:=flag.NewFlagSet("tls",flag.ContinueOnError)
 port:=fs.Int("port",443,"TLS port")
 timeout:=fs.Duration("timeout",5*time.Second,"connection timeout")
 output:=fs.String("output","text","text or json")
 lang:=fs.String("lang","zh","zh or en")
 if err:=fs.Parse(args);err!=nil{return err}
 if *port<1||*port>65535{return errors.New("-port must be between 1 and 65535")}
 if *timeout<=0{return errors.New("-timeout must be positive")}
 if *lang!="zh"&&*lang!="en"{return errors.New("-lang must be zh or en")}
 format,err:=resolveOutputFormat(*output,false)
 if err!=nil{return err}
 if fs.NArg()!=1||!validTLSTarget(fs.Arg(0)){return fmt.Errorf("expected one valid hostname or IP")}
 report:=inspectTLS(strings.TrimSuffix(fs.Arg(0),"."),*port,*timeout)
 if format=="json"{
  b,err:=json.MarshalIndent(report,"","  ")
  if err!=nil{return err}
  fmt.Println(string(b))
 }else{
  name:=func(zh,en string)string{if *lang=="en"{return en};return zh}
  fmt.Printf("%s: %s:%d\n",name("TLS 目标","TLS target"),report.Host,report.Port)
  if !report.Connected{
   fmt.Printf("  %s: %s\n",name("连接失败","Connection failed"),report.ConnectionError)
  }else{
   fmt.Printf("  %s: %s | %s | %s: %dms\n",name("握手成功","Handshake OK"),report.TLSVersion,report.CipherSuite,name("耗时","Duration"),report.DurationMS)
   if report.ALPN!=""{fmt.Printf("  ALPN: %s\n",report.ALPN)}
   fmt.Printf("  %s: %s\n",name("证书主题","Subject"),report.Subject)
   fmt.Printf("  %s: %s\n",name("颁发者","Issuer"),report.Issuer)
   fmt.Printf("  %s: %s\n",name("到期时间","Expires"),report.NotAfter)
   fmt.Printf("  %s: %d\n",name("剩余天数","Days remaining"),report.DaysRemaining)
   fmt.Printf("  %s: %t\n",name("证书有效","Certificate verified"),report.Verified)
   if report.VerificationError!=""{fmt.Printf("  %s: %s\n",name("验证错误","Verification error"),report.VerificationError)}
  }
 }
 if !report.Connected||!report.Verified{return fmt.Errorf("TLS connection or certificate verification failed")}
 return nil
}

var _ = os.Stderr
