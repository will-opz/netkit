package main

import (
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "os/exec"
 "runtime"
 "strings"
 "time"
 "context"
 "net"
 "net/netip"
)

// DNSResolver describes OS resolver configuration, not proof of which upstream
// server a particular application uses (e.g. DoH and VPN overrides).
type DNSResolver struct {
 Source string `json:"source"`
 Index int `json:"index,omitempty"`
 Nameservers []string `json:"nameservers,omitempty"`
 Domain string `json:"domain,omitempty"`
 SearchDomains []string `json:"search_domains,omitempty"`
 Interface string `json:"interface,omitempty"`
 Flags string `json:"flags,omitempty"`
}
type DNSConfig struct {
 Platform string `json:"platform"`
 Resolvers []DNSResolver `json:"resolvers"`
 Warnings []string `json:"warnings,omitempty"`
}
type PublicDNS struct {
 Name string `json:"name"`
 IPv4 []string `json:"ipv4"`
 IPv6 []string `json:"ipv6"`
 DoH string `json:"doh,omitempty"`
 NoteZH string `json:"-"`
 NoteEN string `json:"-"`
}
var publicDNS = []PublicDNS{
 {Name:"Cloudflare",IPv4:[]string{"1.1.1.1","1.0.0.1"},IPv6:[]string{"2606:4700:4700::1111","2606:4700:4700::1001"},DoH:"https://cloudflare-dns.com/dns-query",NoteZH:"公共解析",NoteEN:"Public resolver"},
 {Name:"Google Public DNS",IPv4:[]string{"8.8.8.8","8.8.4.4"},IPv6:[]string{"2001:4860:4860::8888","2001:4860:4860::8844"},DoH:"https://dns.google/dns-query",NoteZH:"公共解析",NoteEN:"Public resolver"},
 {Name:"Quad9",IPv4:[]string{"9.9.9.9","149.112.112.112"},IPv6:[]string{"2620:fe::fe","2620:fe::9"},DoH:"https://dns.quad9.net/dns-query",NoteZH:"威胁拦截配置",NoteEN:"Threat-blocking configuration"},
 {Name:"AdGuard DNS",IPv4:[]string{"94.140.14.14","94.140.15.15"},IPv6:[]string{"2a10:50c0::ad1:ff","2a10:50c0::ad2:ff"},DoH:"https://dns.adguard-dns.com/dns-query",NoteZH:"广告与跟踪拦截配置",NoteEN:"Ad/tracker filtering"},
}
func parseResolvConf(raw string) []DNSResolver {
 r:=DNSResolver{Source:"/etc/resolv.conf"}
 for _,line:=range strings.Split(raw,"\n"){
  line=strings.TrimSpace(strings.SplitN(strings.SplitN(line,"#",2)[0],";",2)[0])
  fields:=strings.Fields(line);if len(fields)<2{continue}
  switch fields[0] {
  case "nameserver":
   if ip:=net.ParseIP(fields[1]);ip!=nil{r.Nameservers=append(r.Nameservers,ip.String())}
  case "search":r.SearchDomains=append(r.SearchDomains,fields[1:]...)
  case "domain":r.Domain=fields[1]
  }
 }
 if len(r.Nameservers)==0 && len(r.SearchDomains)==0 && r.Domain==""{return []DNSResolver{}}
 return []DNSResolver{r}
}
func parseScutilDNS(raw string) []DNSResolver{
 result:=[]DNSResolver{}
 current:=DNSResolver{Source:"scutil --dns"}
 appendCurrent:=func(){if len(current.Nameservers)>0 {result=append(result,current)}}
 for _,line:=range strings.Split(raw,"\n"){
  line=strings.TrimSpace(line)
  if strings.HasPrefix(line,"resolver #"){
   appendCurrent()
   current=DNSResolver{Source:"scutil --dns"}
   fmt.Sscanf(line,"resolver #%d",&current.Index)
   continue
  }
  key,val,ok:=strings.Cut(line,":")
  if !ok{continue}
  key=strings.TrimSpace(key);val=strings.TrimSpace(val)
  switch{
  case strings.HasPrefix(key,"nameserver["):
   if ip:=net.ParseIP(strings.TrimSpace(strings.SplitN(val,"%",2)[0]));ip!=nil {current.Nameservers=append(current.Nameservers,val)}
  case key=="domain":current.Domain=val
  case strings.HasPrefix(key,"search domain["):current.SearchDomains=append(current.SearchDomains,val)
  case key=="if_index":current.Interface=val
  case key=="flags":current.Flags=val
  }
 }
 appendCurrent()
 return result
}
func systemDNS()DNSConfig{
 info:=DNSConfig{Platform:runtime.GOOS,Resolvers:[]DNSResolver{}}
 if runtime.GOOS=="darwin"{
  ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
  raw,err:=exec.CommandContext(ctx,"scutil","--dns").Output()
  cancel()
  if err==nil {info.Resolvers=parseScutilDNS(string(raw))
  }else{info.Warnings=append(info.Warnings,"scutil --dns: "+err.Error())}
 }
 if runtime.GOOS=="linux"||len(info.Resolvers)==0 {
  raw,err:=os.ReadFile("/etc/resolv.conf")
  if err==nil {
   info.Resolvers=append(info.Resolvers,parseResolvConf(string(raw))...)
   if runtime.GOOS=="darwin" {info.Warnings=append(info.Warnings,"fallback /etc/resolv.conf; macOS scoped DNS may be missing")}
  }else{info.Warnings=append(info.Warnings,"/etc/resolv.conf: "+err.Error())}
 }
 if len(info.Resolvers)==0{info.Warnings=append(info.Warnings,"no resolvers discovered")}
 return info
}
func dnsHelp() {
 fmt.Println("用法: netkit dns [list|compare|query] [--output text|json] [-lang zh|en]")
 fmt.Println("  netkit dns           本机 DNS 配置")
 fmt.Println("  netkit dns list      常见公共 DNS（静态目录，非实时测速）")
 fmt.Println("  netkit dns compare baidu.com  比较系统、Cloudflare、Google 解析结果")
 fmt.Println("  netkit dns compare -detail -type A baidu.com  附加公共 DoH RCODE/TTL 对比")
 fmt.Println("  netkit dns query -type SOA example.com  查询 RCODE/TTL/原始记录（DoH）")
}
func runDNS(args []string)error{
 if len(args)>0&&(args[0]=="-h"||args[0]=="--help"||args[0]=="help"){dnsHelp();return nil}
 if len(args)>0&&args[0]=="query"{return runDNSQuery(args[1:])}
 listing:=false
 comparing:=false
 if len(args)>0&&args[0]=="list" {listing=true;args=args[1:]}
 if len(args)>0&&args[0]=="compare" {comparing=true;args=args[1:]}
 fs:=flag.NewFlagSet("dns",flag.ContinueOnError)
 output:=fs.String("output","text","text/json")
 lang:=fs.String("lang","zh","zh/en")
 timeout:=fs.Duration("timeout",5*time.Second,"query timeout")
 detail:=fs.Bool("detail",false,"add DoH RCODE, answer and TTL comparison")
 recordType:=fs.String("type","A","DoH detailed record type")
 if err:=fs.Parse(args);err!=nil{return err}
 if comparing {if fs.NArg()!=1{return fmt.Errorf("dns compare requires one domain")}} else if fs.NArg()!=0{return fmt.Errorf("dns: unexpected argument %q",fs.Arg(0))}
 format,err:=resolveOutputFormat(*output,false);if err!=nil{return err}
 if *lang!="zh"&&*lang!="en"{return errors.New("lang must be zh or en")}
 if comparing{return runDNSCompare(fs.Arg(0),*timeout,format,*lang,*detail,*recordType)}
 if listing{
  if format=="json"{b,_:=json.MarshalIndent(publicDNS,"","  ");fmt.Println(string(b));return nil}
  fmt.Println("公共 DNS / Public DNS (static reference)")
  for _,p:=range publicDNS{
   note:=p.NoteZH;if *lang=="en"{note=p.NoteEN}
   fmt.Printf("%s | IPv4: %s | IPv6: %s | %s\n",p.Name,strings.Join(p.IPv4,", "),strings.Join(p.IPv6,", "),note)
   fmt.Printf("  DoH: %s\n",p.DoH)
  }
  return nil
 }
 info:=systemDNS()
 if format=="json"{b,_:=json.MarshalIndent(info,"","  ");fmt.Println(string(b));return nil}
 title:="本机 DNS 配置";if *lang=="en"{title="System DNS configuration"}
 fmt.Println(title+" ("+info.Platform+")")
 for _,r:=range info.Resolvers{
  fmt.Printf("  [%s",r.Source)
  if r.Index!=0{fmt.Printf(" #%d",r.Index)}
  fmt.Print("] ")
  fmt.Println(strings.Join(r.Nameservers,", "))
  if r.Domain!=""{fmt.Println("    Domain:",r.Domain)}
  if r.Interface!=""{fmt.Println("    Interface:",r.Interface)}
  if len(r.SearchDomains)>0{fmt.Println("    Search:",strings.Join(r.SearchDomains,", "))}
 }
 for _,warning:=range info.Warnings{fmt.Fprintln(os.Stderr,"DNS:",warning)}
 return nil
}

// KnownDNS is a positive, exact match against the built-in public DNS list.
// A nil match only means "not listed"; it does not prove a host is not a DNS resolver.
type KnownDNS struct {
 Provider string `json:"provider"`
 Role string `json:"role"`
 Match string `json:"match"`
 DoH string `json:"doh,omitempty"`
}
func identifyPublicDNS(raw string)*KnownDNS {
 target,err:=netip.ParseAddr(raw)
 if err!=nil||target.Zone()!="" {return nil}
 target=target.Unmap()
 for _,p:=range publicDNS {
  for _,address:=range append(append([]string{},p.IPv4...),p.IPv6...){
   parsed,err:=netip.ParseAddr(address)
   if err!=nil{continue}
   if parsed.Unmap()==target{
    return &KnownDNS{Provider:p.Name,Role:"public_recursive_resolver",Match:"static_exact_ip",DoH:p.DoH}
   }
  }
 }
 return nil
}
