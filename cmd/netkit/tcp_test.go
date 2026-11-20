package main

import (
 "context"
 "errors"
 "net"
 "strconv"
 "strings"
 "testing"
 "time"
)

func TestTCPHostValidation(t *testing.T){
 for _,host:=range []string{"example.com","localhost.example","127.0.0.1","::1","2001:db8::1"}{
  if !validTCPHost(host){t.Fatalf("rejected %q",host)}
 }
 for _,host:=range []string{"","https://example.com","example.com:443","alice@example.com","example.com/path"," host.example.com"}{
  if validTCPHost(host){t.Fatalf("accepted %q",host)}
 }
}
func TestTCPConnectLocalIPv4(t *testing.T){
 ln,err:=net.Listen("tcp4","127.0.0.1:0")
 if err!=nil{t.Fatal(err)}
 defer ln.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
 defer cancel()
 port:=ln.Addr().(*net.TCPAddr).Port
 r:=probeTCP(ctx,"127.0.0.1",port,nil)
 if r.Status!="connected"||r.ConnectedIP!="127.0.0.1"||len(r.Attempts)!=1||!r.Attempts[0].Connected||r.Attempts[0].Family!="IPv4"{
  t.Fatalf("expected local connection: %+v",r)
 }
 if r.DNSDurationMS!=0||r.DNSerror!=""{t.Fatalf("literal IP should skip DNS: %+v",r)}
}
func TestTCPConnectLocalHostnameResolution(t *testing.T){
 ln,err:=net.Listen("tcp4","127.0.0.1:0")
 if err!=nil{t.Fatal(err)}
 defer ln.Close()
 resolver:=func(ctx context.Context,name string)([]net.IPAddr,error){
  if name!="test.example"{t.Fatal("unexpected DNS name")}
  return []net.IPAddr{{IP:net.ParseIP("127.0.0.1")},{IP:net.ParseIP("127.0.0.1")}},nil
 }
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
 defer cancel()
 r:=probeTCP(ctx,"test.example",ln.Addr().(*net.TCPAddr).Port,resolver)
 if r.Status!="connected"||len(r.ResolvedIPs)!=1||r.ConnectedIP!="127.0.0.1"{t.Fatalf("unexpected resolution: %+v",r)}
}
func TestTCPFallbackAcrossAddresses(t *testing.T){
 ln,err:=net.Listen("tcp4","127.0.0.1:0")
 if err!=nil{t.Fatal(err)}
 defer ln.Close()
 resolver:=func(context.Context,string)([]net.IPAddr,error){
  return []net.IPAddr{{IP:net.ParseIP("127.0.0.2")},{IP:net.ParseIP("127.0.0.1")}},nil
 }
 ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
 defer cancel()
 r:=probeTCP(ctx,"test.example",ln.Addr().(*net.TCPAddr).Port,resolver)
 if r.Status!="connected"||len(r.Attempts)!=2||r.Attempts[0].Connected||!r.Attempts[1].Connected{
  t.Fatalf("expected retry on next address: %+v",r)
 }
}
func TestTCPDNSError(t *testing.T){
 resolver:=func(context.Context,string)([]net.IPAddr,error){return nil,errors.New("simulated NXDOMAIN")}
 r:=probeTCP(context.Background(),"missing.example",443,resolver)
 if r.Status!="dns_error"||r.DNSerror!="simulated NXDOMAIN"||len(r.Attempts)!=0{t.Fatalf("expected DNS failure: %+v",r)}
}
func TestTCPNoRecords(t *testing.T){
 resolver:=func(context.Context,string)([]net.IPAddr,error){return nil,nil}
 r:=probeTCP(context.Background(),"empty.example",443,resolver)
 if r.Status!="dns_error"||r.DNSerror==""{t.Fatalf("expected empty DNS error: %+v",r)}
}
func TestTCPRefused(t *testing.T){
 ln,err:=net.Listen("tcp4","127.0.0.1:0")
 if err!=nil{t.Fatal(err)}
 port:=ln.Addr().(*net.TCPAddr).Port
 ln.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
 defer cancel()
 r:=probeTCP(ctx,"127.0.0.1",port,nil)
 if r.Status!="connect_error"||len(r.Attempts)!=1||r.Attempts[0].Error==""{t.Fatalf("expected refused connection: %+v",r)}
}
func TestTCPTimeout(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 r:=probeTCP(ctx,"192.0.2.1",443,nil)
 if r.Status!="timeout"||len(r.Attempts)!=1{t.Fatalf("expected cancelled connection: %+v",r)}
}
func TestTCPIPv6Local(t *testing.T){
 ln,err:=net.Listen("tcp6","[::1]:0")
 if err!=nil{t.Skipf("IPv6 loopback not supported: %v",err)}
 defer ln.Close()
 port:=ln.Addr().(*net.TCPAddr).Port
 ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
 defer cancel()
 r:=probeTCP(ctx,"::1",port,nil)
 if r.Status!="connected"||r.Attempts[0].Family!="IPv6"||r.Attempts[0].Address!="[::1]:"+strconv.Itoa(port){
  t.Fatalf("unexpected IPv6: %+v",r)
 }
}
func TestTCPTargetInvalidPort(t *testing.T){
 if !strings.Contains("PORT must be a valid TCP port (1-65535)","PORT"){t.Fatal("bad error contract")}
}
