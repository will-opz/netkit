package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "os"
 "os/exec"
 "path/filepath"
 "runtime"
 "encoding/binary"
 "encoding/hex"
 "sort"
 "strconv"
 "strings"
 "sync"
 "time"
)

const agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
const limit = 1 << 20

type Source struct {
 Name string `json:"name"`
 URL string `json:"url,omitempty"`
 Data map[string]any `json:"data,omitempty"`
 Error string `json:"error,omitempty"`
 DurationMS int64 `json:"duration_ms"`
}
type Registry struct {
 Servers []string `json:"servers,omitempty"`
 Range string `json:"range,omitempty"`
 CIDR string `json:"cidr,omitempty"`
 NetName string `json:"netname,omitempty"`
 Organization string `json:"organization,omitempty"`
 Country string `json:"country,omitempty"`
 ASN string `json:"asn,omitempty"`
 AbuseEmail string `json:"abuse_email,omitempty"`
 Raw string `json:"raw,omitempty"`
 Error string `json:"error,omitempty"`
}
type Agreement struct {
 Value string `json:"value"`
 Agree int `json:"agree"`
 Reported int `json:"reported"`
 Sources []string `json:"sources,omitempty"`
 Alternatives map[string][]string `json:"alternatives,omitempty"`
}
type Summary struct {
 Country string `json:"country,omitempty"`
 Region string `json:"region,omitempty"`
 City string `json:"city,omitempty"`
 ISP string `json:"isp,omitempty"`
 Organization string `json:"organization,omitempty"`
 ASN string `json:"asn,omitempty"`
 Timezone string `json:"timezone,omitempty"`
 Hosting *bool `json:"hosting,omitempty"`
 Proxy *bool `json:"proxy,omitempty"`
 RegisteredCountry string `json:"registered_country,omitempty"`
 Network string `json:"network,omitempty"`
 AbuseEmail string `json:"abuse_email,omitempty"`
 Agreements map[string]Agreement `json:"agreements,omitempty"`
}
type Result struct {
 IP string `json:"ip"`
 Scope string `json:"scope,omitempty"`
 Summary Summary `json:"summary"`
 Sources []Source `json:"sources,omitempty"`
 Whois Registry `json:"whois"`
}

type InterfaceInfo struct {
 Name string `json:"name"`
 Addresses []string `json:"addresses"`
 Flags string `json:"flags,omitempty"`
}
type GatewayInfo struct {
 Family string `json:"family"`
 Gateway string `json:"gateway"`
 Interface string `json:"interface,omitempty"`
}
type LocalReport struct {
 Hostname string `json:"hostname,omitempty"`
 LocalIP string `json:"local_ip,omitempty"`
 Interfaces []InterfaceInfo `json:"interfaces"`
 Gateways []GatewayInfo `json:"gateways"`
 PublicIP string `json:"public_ip,omitempty"`
 Public *Result `json:"public,omitempty"`
 Warnings []string `json:"warnings,omitempty"`
}

type provider struct { name, endpoint string }
var providers = []provider{
 {"ip-api.com", "http://ip-api.com/json/%s?lang=zh-CN&fields=66846719"},
 {"ipwho.is", "https://ipwho.is/%s"},
 {"ipinfo.io", "https://ipinfo.io/%s/json"},
 {"api.ip.sb", "https://api.ip.sb/geoip/%s"},
}

// With no subcommand, show the same local-network report as "netkit ip".
// Explicit help and future subcommands continue to use the existing dispatcher.
func defaultCommandArgs(args []string) []string {
 if len(args)==1 {return append(args,"ip")}
 return args
}
func main() {
 os.Args=defaultCommandArgs(os.Args)
 if len(os.Args)<2 || os.Args[1]=="-h" || os.Args[1]=="--help" || os.Args[1]=="help" {
  fmt.Println("NetKit：网络诊断工具箱")
  fmt.Println("Usage: netkit ip [options] [IPv4|IPv6 ...]")
  fmt.Println("子命令:\n  ip    多数据源 IP 信息与 WHOIS 查询")
  fmt.Println("使用 netkit ip -h 查看参数；不指定 IP 时查看本机网卡、网关和公网 IP。")
  return
 }
 if os.Args[1]!="ip" {
  fmt.Fprintln(os.Stderr,"未知子命令:",os.Args[1])
  fmt.Fprintln(os.Stderr,"Usage: netkit ip [options] [IPv4|IPv6 ...]")
  os.Exit(2)
 }
 os.Args=append([]string{os.Args[0]},os.Args[2:]...)
 all := flag.Bool("all", false, "显示各接口原始结果及 WHOIS")
 whoisOnly := flag.Bool("whois", false, "仅查询原生 WHOIS（TCP 43）")
 jsonFlag := flag.Bool("json", false, "输出 JSON（字段名固定为英文）")
 timeout := flag.Duration("timeout", 5*time.Second, "每个请求的超时时间")
 lang := flag.String("lang", "zh", "输出语言：zh（默认中文）、en（英文）")
 flag.Usage = func() {
  fmt.Fprintln(flag.CommandLine.Output(), "Usage: netkit ip [options] [IPv4|IPv6 ...]")
  fmt.Fprintln(flag.CommandLine.Output(), "不指定 IP 时显示本机接口、默认网关并检测公网 IP。")
  flag.PrintDefaults()
 }
 flag.Parse()
 *lang = strings.ToLower(strings.TrimSpace(*lang))
 if *lang!="zh" && *lang!="en" {fmt.Fprintln(os.Stderr,"-lang 仅支持 zh 或 en / supported: zh, en");os.Exit(2)}
 if *timeout <= 0 { fmt.Fprintln(os.Stderr, "超时时间必须大于 0"); os.Exit(2) }
 client := &http.Client{Transport: &http.Transport{Proxy:http.ProxyFromEnvironment, MaxIdleConns:16, IdleConnTimeout:30*time.Second}}
 ips := flag.Args()
 if len(ips)==0 {
  report:=inspectLocal(client,*timeout,*whoisOnly)
  if *jsonFlag {
   b,err:=json.MarshalIndent(report,"","  ")
   if err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
   fmt.Println(string(b))
  } else {
   printLocal(report,*lang,*all,*whoisOnly)
  }
  return
 }
 results:=make([]Result,0,len(ips))
 seen:=map[string]bool{}
 invalid:=false
 for _,input:=range ips {
  ip:=net.ParseIP(input)
  if ip==nil {fmt.Fprintln(os.Stderr,"无效 IP:",input);invalid=true;continue}
  key:=ip.String()
  if seen[key] {continue};seen[key]=true
  results=append(results,lookup(client,key,*timeout,*whoisOnly))
 }
 if *jsonFlag {
  b,err:=json.MarshalIndent(results,"","  ")
  if err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
  fmt.Println(string(b))
 } else {
  for _,r:=range results {
   if *all {printResult(r,true,*whoisOnly,*lang)} else {printCompact(r,*whoisOnly,*lang)}
  }
 }
 if invalid||len(results)==0 {os.Exit(2)}
}

func getHTTP(ctx context.Context,client *http.Client,endpoint,accept string)([]byte,int,error){
 req,err:=http.NewRequestWithContext(ctx,http.MethodGet,endpoint,nil)
 if err!=nil {return nil,0,err}
 req.Header.Set("User-Agent",agent)
 req.Header.Set("Accept",accept)
 resp,err:=client.Do(req)
 if err!=nil {return nil,0,err}
 defer resp.Body.Close()
 b,err:=io.ReadAll(io.LimitReader(resp.Body,limit+1))
 if err!=nil {return nil,resp.StatusCode,err}
 if len(b)>limit {return nil,resp.StatusCode,errors.New("response too large")}
 return b,resp.StatusCode,nil
}
func publicIP(client *http.Client,timeout time.Duration)(string,error){
 var problems []string
 for _,endpoint:=range []string{"https://api.ipify.org","https://ifconfig.me/ip","https://icanhazip.com"}{
  ctx,cancel:=context.WithTimeout(context.Background(),timeout)
  body,status,err:=getHTTP(ctx,client,endpoint,"text/plain")
  cancel()
  if err==nil && status==200 {
   if ip:=net.ParseIP(strings.TrimSpace(string(body)));ip!=nil&&ip.IsGlobalUnicast(){return ip.String(),nil}
  }
  problems=append(problems,fmt.Sprintf("%s: status %d, %v",endpoint,status,err))
 }
 return "",errors.New(strings.Join(problems,"; "))
}
func lookup(client *http.Client,ip string,timeout time.Duration,whoisOnly bool) Result {
 r:=Result{IP:ip}
 r.Scope=ipScope(net.ParseIP(ip))
 if r.Scope!="public" {return r}
 if whoisOnly {
  r.Whois=queryWhois(ip,timeout)
  r.Summary=aggregate(nil,r.Whois)
  return r
 }
 r.Sources=make([]Source,len(providers))
 var wg sync.WaitGroup
 for i,p:=range providers {
  wg.Add(1)
  go func(i int,p provider){defer wg.Done();r.Sources[i]=geo(client,ip,p,timeout)}(i,p)
 }
 wg.Add(1)
 go func(){defer wg.Done();r.Whois=queryWhois(ip,timeout)}()
 wg.Wait()
 r.Summary=aggregate(r.Sources,r.Whois)
 return r
}
func geo(client *http.Client,ip string,p provider,timeout time.Duration)(s Source) {
 start:=time.Now()
 s=Source{Name:p.name,URL:fmt.Sprintf(p.endpoint,url.PathEscape(ip))}
 defer func(){s.DurationMS=time.Since(start).Milliseconds()}()
 ctx,cancel:=context.WithTimeout(context.Background(),timeout)
 defer cancel()
 body,status,err:=getHTTP(ctx,client,s.URL,"application/json")
 if err!=nil {s.Error=err.Error();return}
 // Keep API error bodies for source comparison where JSON is available.
 if json.Unmarshal(body,&s.Data)!=nil {s.Error=fmt.Sprintf("HTTP %d: invalid JSON",status);return}
 if status<200||status>=300 {s.Error=fmt.Sprintf("HTTP %d",status);return}
 if p.name=="ip-api.com" && value(s.Data,"status")!="success" {s.Error="API: "+value(s.Data,"message")}
 if p.name=="ipwho.is" && s.Data["success"]==false {s.Error="API: "+value(s.Data,"message")}
 if p.name=="ipinfo.io" && s.Data["bogon"]==true {s.Error="bogon address"}
 if p.name=="api.ip.sb" && value(s.Data,"message")!="" && value(s.Data,"ip")=="" {s.Error="API: "+value(s.Data,"message")}
 return
}

func value(m map[string]any,keys ...string)string {
 for _,k:=range keys {
  v,ok:=m[k];if !ok||v==nil {continue}
  switch x:=v.(type) {
  case string:if strings.TrimSpace(x)!="" {return strings.TrimSpace(x)}
  case float64:return strconv.FormatFloat(x,'f',-1,64)
  case bool:return strconv.FormatBool(x)
  }
 }
 return ""
}
func object(m map[string]any,key string)map[string]any {x,_:=m[key].(map[string]any);return x}
func first(values ...string)string {for _,v:=range values {if strings.TrimSpace(v)!="" {return strings.TrimSpace(v)}};return ""}
func normalizeASN(v string)string {
 f:=strings.Fields(strings.ToUpper(strings.TrimSpace(v)))
 if len(f)==0 {return ""}
 n:=strings.TrimPrefix(f[0],"AS")
 if _,err:=strconv.ParseUint(n,10,32);err!=nil {return ""}
 return "AS"+n
}
func field(s Source,key string)string {
 if s.Error!=""||s.Data==nil {return ""}
 m:=s.Data
 switch s.Name {
 case "ip-api.com":
  switch key {
  case "country":return value(m,"countryCode")
  case "region":return value(m,"regionName")
  case "city":return value(m,"city")
  case "asn":return normalizeASN(value(m,"as"))
  case "isp":return value(m,"isp")
  case "organization":return value(m,"org")
  }
 case "ipwho.is":
  c:=object(m,"connection")
  switch key {
  case "country":return value(m,"country_code")
  case "region":return value(m,"region")
  case "city":return value(m,"city")
  case "asn":return normalizeASN(value(c,"asn"))
  case "isp":return value(c,"isp")
  case "organization":return value(c,"org")
  }
 case "ipinfo.io":
  switch key {
  case "country":return value(m,"country")
  case "region":return value(m,"region")
  case "city":return value(m,"city")
  case "asn":return normalizeASN(value(m,"org"))
  case "organization":
   org:=value(m,"org");f:=strings.Fields(org)
   if len(f)>1&&normalizeASN(f[0])!="" {return strings.Join(f[1:]," ")}
   return org
  }
 case "api.ip.sb":
  switch key {
  case "country":return value(m,"country_code")
  case "region":return value(m,"region")
  case "city":return value(m,"city")
  case "asn":return normalizeASN(value(m,"asn"))
  case "isp":return value(m,"isp")
  case "organization":return value(m,"organization","asn_organization")
  }
 }
 return ""
}
func vote(sources []Source,key string)Agreement {
 groups:=map[string][]string{}
 values:=map[string]string{}
 for _,s:=range sources {
  v:=field(s,key);if v=="" {continue}
  k:=strings.ToLower(strings.TrimSpace(v))
  groups[k]=append(groups[k],s.Name)
  if values[k]=="" {values[k]=v}
 }
 a:=Agreement{}
 best:=""
 for _,s:=range sources {
  k:=strings.ToLower(strings.TrimSpace(field(s,key)))
  if k!="" && (best==""||len(groups[k])>len(groups[best])) {best=k}
 }
 for _,names:=range groups {a.Reported+=len(names)}
 if best!="" {a.Value=values[best];a.Agree=len(groups[best]);a.Sources=groups[best]}
 for k,names:=range groups {
  if k==best {continue}
  if a.Alternatives==nil {a.Alternatives=map[string][]string{}}
  a.Alternatives[values[k]]=names
 }
 return a
}
func aggregate(sources []Source,w Registry)Summary {
 s:=Summary{RegisteredCountry:w.Country,Network:first(w.CIDR,w.Range),AbuseEmail:w.AbuseEmail}
 keys:=[]string{"country","region","city","asn","isp","organization"}
 for _,k:=range keys {
  a:=vote(sources,k)
  if a.Reported==0 {continue}
  if s.Agreements==nil {s.Agreements=map[string]Agreement{}}
  s.Agreements[k]=a
  switch k {
  case "country":s.Country=a.Value
  case "region":s.Region=a.Value
  case "city":s.City=a.Value
  case "asn":s.ASN=a.Value
  case "isp":s.ISP=a.Value
  case "organization":s.Organization=a.Value
  }
 }
 for _,src:=range sources {
  if src.Error!="" {continue}
  switch src.Name {
  case "ip-api.com":
   if s.Timezone=="" {s.Timezone=value(src.Data,"timezone")}
   if s.Proxy==nil {if v,ok:=src.Data["proxy"].(bool);ok {s.Proxy=&v}}
   if s.Hosting==nil {if v,ok:=src.Data["hosting"].(bool);ok {s.Hosting=&v}}
  case "ipwho.is":
   if s.Timezone=="" {s.Timezone=value(object(src.Data,"timezone"),"id")}
  case "ipinfo.io","api.ip.sb":
   if s.Timezone=="" {s.Timezone=value(src.Data,"timezone")}
  }
 }
 s.ASN=first(s.ASN,normalizeASN(w.ASN))
 s.Organization=first(s.Organization,w.Organization)
 return s
}

var allowedWhois=map[string]bool{
 "whois.iana.org":true,"whois.apnic.net":true,"whois.arin.net":true,
 "whois.ripe.net":true,"whois.lacnic.net":true,"whois.afrinic.net":true,
}
func registryServer(raw string)string {
 raw=strings.TrimSpace(raw)
 if strings.Contains(raw,"://") {
  u,err:=url.Parse(raw)
  if err!=nil||(u.Scheme!="whois"&&u.Scheme!="rwhois"){return ""}
  if port:=u.Port();port!=""&&port!="43" {return ""}
  raw=u.Hostname()
 }
 raw=strings.ToLower(strings.TrimSuffix(raw,"."))
 if !allowedWhois[raw] {return ""}
 return raw
}
func referral(raw string)string {
 for _,line:=range strings.Split(raw,"\n"){
  key,val,ok:=strings.Cut(strings.TrimSpace(line),":")
  if !ok {continue}
  key=strings.ToLower(strings.TrimSpace(key))
  if key!="refer"&&key!="referralserver" {continue}
  parts:=strings.Fields(strings.TrimSpace(val))
  if len(parts)==0 {continue}
  if host:=registryServer(parts[0]);host!="" {return host}
 }
 return ""
}
func whoisCall(server,ip string,timeout time.Duration)(string,error) {
 ctx,cancel:=context.WithTimeout(context.Background(),timeout)
 defer cancel()
 conn,err:=(&net.Dialer{Timeout:timeout}).DialContext(ctx,"tcp",net.JoinHostPort(server,"43"))
 if err!=nil {return "",err}
 defer conn.Close()
 if err=conn.SetDeadline(time.Now().Add(timeout));err!=nil {return "",err}
 q:=ip
 if server=="whois.arin.net" {q="n + "+ip}
 if _,err=io.WriteString(conn,q+"\r\n");err!=nil {return "",err}
 body,err:=io.ReadAll(io.LimitReader(conn,limit+1))
 if err!=nil {return "",err}
 if len(body)>limit {return "",errors.New("WHOIS response too large")}
 return string(body),nil
}
func whoisFields(raw string,w *Registry){
 data:=map[string][]string{}
 for _,line:=range strings.Split(raw,"\n"){
  line=strings.TrimSpace(line)
  if line==""||strings.HasPrefix(line,"#")||strings.HasPrefix(line,"%"){continue}
  key,val,ok:=strings.Cut(line,":")
  if !ok {continue}
  k:=strings.ToLower(strings.TrimSpace(key));v:=strings.TrimSpace(val)
  if v!="" {data[k]=append(data[k],v)}
 }
 get:=func(keys ...string)string {
  for _,k:=range keys {if v:=data[k];len(v)>0 {return v[0]}}
  return ""
 }
 if v:=get("inetnum","inet6num","netrange");v!="" {w.Range=v}
 if v:=get("cidr");v!="" {w.CIDR=v}
 if v:=get("netname");v!="" {w.NetName=v}
 if v:=get("orgname","org-name","owner","organization","descr");v!="" {w.Organization=v}
 if v:=get("country");v!="" {w.Country=v}
 if v:=get("origin","originas");v!="" {w.ASN=normalizeASN(v)}
 if v:=get("abuse-mailbox","orgabuseemail");strings.Contains(v,"@") {w.AbuseEmail=v}
}
func queryWhois(ip string,timeout time.Duration)Registry {
 r:=Registry{}
 server:="whois.iana.org"
 seen:=map[string]bool{}
 deadline:=time.Now().Add(2*timeout)
 for depth:=0;depth<4;depth++{
  server=registryServer(server)
  if server==""||seen[server] {break}
  seen[server]=true
  remaining:=time.Until(deadline)
  if remaining<=0 {r.Error="WHOIS total timeout";break}
  if remaining>timeout {remaining=timeout}
  r.Servers=append(r.Servers,server)
  raw,err:=whoisCall(server,ip,remaining)
  if err!=nil {r.Error=fmt.Sprintf("%s: %v",server,err);break}
  r.Raw+=fmt.Sprintf("--- %s ---\n%s\n",server,raw)
  whoisFields(raw,&r)
  server=referral(raw)
  if server=="" {break}
 }
 return r
}
func printResult(r Result,all,whoisOnly bool,lang string){
 fmt.Printf("\nIP: %s\n",r.IP)
 if r.Scope!="" && r.Scope!="public" {fmt.Println("  "+translate(lang,"addressType")+": "+scopeLabel(lang,r.Scope));return}
 s:=r.Summary
 items:=[][2]string{
  {translate(lang,"country"),countryName(lang,s.Country)}, {translate(lang,"region"),s.Region},{translate(lang,"city"),s.City},{"ISP",s.ISP},
  {translate(lang,"organization"),s.Organization},{"ASN",s.ASN},{translate(lang,"timezone"),s.Timezone},
  {translate(lang,"registeredCountry"),countryName(lang,s.RegisteredCountry)},{translate(lang,"network"),s.Network},{translate(lang,"abuseEmail"),s.AbuseEmail},
 }
 for _,pair:=range items {if pair[1]!="" {fmt.Printf("  %-18s %s\n",pair[0]+":",pair[1])}}
 if s.Hosting!=nil {fmt.Printf("  %s: %s (%s)\n",translate(lang,"hosting"),yesNo(lang,*s.Hosting),translate(lang,"providerObservation"))}
 if s.Proxy!=nil {fmt.Printf("  %s: %s (%s)\n",translate(lang,"proxy"),yesNo(lang,*s.Proxy),translate(lang,"providerObservation"))}
 keys:=make([]string,0,len(s.Agreements))
 for k:=range s.Agreements {keys=append(keys,k)}
 sort.Strings(keys)
 for _,k:=range keys {
  a:=s.Agreements[k]
  fmt.Printf("  %s: %d/%d %s\n",translate(lang,k),a.Agree,a.Reported,translate(lang,"agree"))
  if len(a.Alternatives)>0 {fmt.Printf("    %s: %v\n",translate(lang,"alternatives"),a.Alternatives)}
 }
 if len(r.Whois.Servers)>0 {fmt.Println("  "+translate(lang,"whoisPath")+": "+strings.Join(r.Whois.Servers," -> "))}
 if r.Whois.Error!="" {fmt.Println("  "+translate(lang,"whoisError")+": "+r.Whois.Error)}
 if whoisOnly||all {
  if r.Whois.Raw!="" {fmt.Printf("\n[%s]\n%s\n",translate(lang,"whoisRaw"),r.Whois.Raw)}
 }
 if all&&!whoisOnly {
  for _,src:=range r.Sources {
   fmt.Printf("\n[%s] %dms %s\n",src.Name,src.DurationMS,src.URL)
   if src.Error!="" {fmt.Println(translate(lang,"error")+":",src.Error)}
   if src.Data!=nil {b,_:=json.MarshalIndent(src.Data,"","  ");fmt.Println(string(b))}
  }
 }
}

// The localization boundary applies to human-readable terminal output only.
// JSON keys and source payloads remain stable across languages.
var messages = map[string]map[string]string{
 "zh": {
  "country":"国家","region":"地区","city":"城市","organization":"组织","timezone":"时区",
  "registeredCountry":"WHOIS 注册国家","network":"注册网段","abuseEmail":"滥用投诉邮箱",
  "hosting":"机房","proxy":"代理","providerObservation":"数据源检测",
  "agree":"个数据源一致","alternatives":"其他结果","whoisPath":"WHOIS 查询路径",
  "whoisError":"WHOIS 错误","whoisRaw":"WHOIS 原始数据","error":"错误",
  "yes":"是","no":"否","unknown":"未知","unavailable":"不可用",
  "sources":"数据源","geoDifference":"GeoIP 差异","sourceFailure":"GeoIP 全部失败",
  "addressType":"地址类型","localNoQuery":"跳过公网 GeoIP/WHOIS","host":"主机名","localIP":"本机出口内网 IP","interfaces":"网络接口","gateways":"默认网关","publicIP":"公网 IP","publicDetail":"公网信息","warnings":"提示","unavailableGW":"未能检测默认网关","networkOverview":"本机网络概览","hiddenInterfaces":"已隐藏 %d 个其他接口（-all 查看）",
 },
 "en": {
  "country":"Country","region":"Region","city":"City","organization":"Organization","timezone":"Timezone",
  "registeredCountry":"WHOIS country","network":"Network","abuseEmail":"Abuse email",
  "hosting":"Hosting","proxy":"Proxy","providerObservation":"provider observation",
  "agree":"sources agree","alternatives":"alternatives","whoisPath":"WHOIS path",
  "whoisError":"WHOIS error","whoisRaw":"WHOIS raw","error":"Error",
  "yes":"Yes","no":"No","unknown":"Unknown","unavailable":"N/A",
  "sources":"Sources","geoDifference":"GeoIP mismatch","sourceFailure":"All GeoIP sources failed",
  "addressType":"Address type","localNoQuery":"Public GeoIP/WHOIS skipped","host":"Hostname","localIP":"Local outbound IP","interfaces":"Interfaces","gateways":"Default gateways","publicIP":"Public IP","publicDetail":"Public details","warnings":"Warnings","unavailableGW":"Default gateway unavailable","networkOverview":"Local network overview","hiddenInterfaces":"%d additional interfaces hidden (use -all)",
 },
}
func translate(lang,key string)string {
 if labels,ok:=messages[lang];ok {
  if text,ok:=labels[key];ok {return text}
 }
 return key
}
func yesNo(lang string,b bool)string {if b{return translate(lang,"yes")};return translate(lang,"no")}
var zhCountries=map[string]string{
 "US":"美国","CN":"中国","JP":"日本","AU":"澳大利亚","GB":"英国","DE":"德国",
 "FR":"法国","CA":"加拿大","SG":"新加坡","HK":"中国香港","TW":"中国台湾",
 "KR":"韩国","IN":"印度","RU":"俄罗斯","NL":"荷兰","BR":"巴西","VN":"越南",
 "TH":"泰国","MY":"马来西亚","ID":"印度尼西亚","PH":"菲律宾","NZ":"新西兰",
 "CH":"瑞士","SE":"瑞典","NO":"挪威","FI":"芬兰","IT":"意大利","ES":"西班牙",
 "IE":"爱尔兰","PL":"波兰","TR":"土耳其","ZA":"南非","AE":"阿联酋",
 "MX":"墨西哥","AR":"阿根廷","CO":"哥伦比亚","EG":"埃及","IL":"以色列",
}
func countryName(lang,code string)string {
 if lang=="zh" {
  if name,ok:=zhCountries[strings.ToUpper(strings.TrimSpace(code))];ok{return name}
 }
 return code
}
func cleanDisplay(v string)string {
 if strings.TrimSpace(v)=="" {return "-"}
 return strings.Join(strings.Fields(v)," ")
}
func compactLine(r Result,whoisOnly bool,lang string)string {
 if r.Scope!="" && r.Scope!="public" {return r.IP+" | "+translate(lang,"addressType")+": "+scopeLabel(lang,r.Scope)+" | "+translate(lang,"localNoQuery")}
 s:=r.Summary
 country:=s.Country
 if whoisOnly {country=s.RegisteredCountry}
 hosting:=translate(lang,"unknown")
 if s.Hosting!=nil {hosting=yesNo(lang,*s.Hosting)}
 whoisStatus:=translate(lang,"unavailable")
 if len(r.Whois.Servers)>0 && r.Whois.Error=="" && (r.Whois.Range!=""||r.Whois.CIDR!=""||r.Whois.NetName!=""||r.Whois.Organization!="") {
  whoisStatus="OK"
 } else if r.Whois.Error!="" {whoisStatus=translate(lang,"error")}
 if whoisOnly {
  return fmt.Sprintf("%s | WHOIS: %s | %s | %s | %s | %s",
   r.IP,whoisStatus,cleanDisplay(countryName(lang,country)),cleanDisplay(s.ASN),cleanDisplay(s.Organization),cleanDisplay(s.Network))
 }
 ok:=0
 for _,source:=range r.Sources {if source.Error=="" {ok++}}
 differences:=[]string{}
 for _,key:=range []string{"country","region","city","asn"} {
  a,exists:=s.Agreements[key]
  if exists&&len(a.Alternatives)>0 {differences=append(differences,translate(lang,key))}
 }
 line:=fmt.Sprintf("%s | %s | %s | %s | %s: %s | %s: %d/%d | WHOIS: %s",
  r.IP,cleanDisplay(countryName(lang,country)),cleanDisplay(s.ASN),cleanDisplay(s.Organization),
  translate(lang,"hosting"),hosting,translate(lang,"sources"),ok,len(r.Sources),whoisStatus)
 if len(differences)>0 {line+=" | "+translate(lang,"geoDifference")+": "+strings.Join(differences,",")}
 if ok==0 {line+=" | "+translate(lang,"sourceFailure")}
 return line
}
func printCompact(r Result,whoisOnly bool,lang string) {
 fmt.Println(compactLine(r,whoisOnly,lang))
}

// ipScope classifies special-purpose networks before contacting any remote
// GeoIP/WHOIS provider. IsGlobalUnicast alone is insufficient: for example,
// RFC 6598 shared and RFC 5737 documentation addresses pass that test.
var specialRanges = []struct{network,scope string}{
 {"100.64.0.0/10","shared"}, {"192.0.0.0/24","reserved"},
 {"192.0.2.0/24","documentation"},{"198.51.100.0/24","documentation"},
 {"203.0.113.0/24","documentation"},{"198.18.0.0/15","benchmark"},
 {"240.0.0.0/4","reserved"},{"0.0.0.0/8","reserved"},
 {"2001:db8::/32","documentation"},{"2001:10::/28","reserved"},
 {"2001::/32","reserved"},
}
func ipScope(ip net.IP)string {
 if ip==nil{return "invalid"}
 if ip.IsUnspecified(){return "unspecified"}
 if ip.IsLoopback(){return "loopback"}
 if ip.IsLinkLocalUnicast(){return "linklocal"}
 if ip.IsMulticast(){return "multicast"}
 if ip.IsPrivate(){return "private"}
 for _,item:=range specialRanges {
  _,subnet,_:=net.ParseCIDR(item.network)
  if subnet.Contains(ip){return item.scope}
 }
 if !ip.IsGlobalUnicast(){return "reserved"}
 return "public"
}
var scopeNames=map[string][2]string{
 "public":{"公网 IP","Public IP"},
 "private":{"私有内网 IP","Private LAN IP"},
 "shared":{"运营商共享地址 (CGNAT)","Shared address (CGNAT)"},
 "loopback":{"回环地址","Loopback"},
 "linklocal":{"链路本地地址","Link-local"},
 "documentation":{"文档保留地址","Documentation range"},
 "benchmark":{"测试保留地址","Benchmark range"},
 "multicast":{"组播地址","Multicast"},
 "unspecified":{"未指定地址","Unspecified"},
 "reserved":{"特殊保留地址","Reserved range"},
 "invalid":{"无效 IP","Invalid IP"},
}
func scopeLabel(lang,scope string)string {
 pair,ok:=scopeNames[scope]
 if !ok{return scope}
 if lang=="en"{return pair[1]}
 return pair[0]
}

// parseLinuxRoute reads the kernel route table directly, without requiring
// external commands or privileges. Only default routes with the gateway bit
// set are considered, and the lowest metric wins.
func parseLinuxRoute(text string)GatewayInfo {
 var chosen GatewayInfo
 bestMetric:=int64(1<<62)
 for _,line:=range strings.Split(text,"\n") {
  f:=strings.Fields(line)
  if len(f)<8 || f[1]!="00000000" || f[7]!="00000000" {continue}
  flags,err1:=strconv.ParseUint(f[3],16,32)
  metric,err2:=strconv.ParseInt(f[6],10,64)
  value,err3:=strconv.ParseUint(f[2],16,32)
  if err1!=nil||err2!=nil||err3!=nil||(flags&0x3)!=0x3 {continue}
  if metric<bestMetric{
   var buf [4]byte
   binary.LittleEndian.PutUint32(buf[:],uint32(value))
   chosen=GatewayInfo{Family:"IPv4",Gateway:net.IP(buf[:]).String(),Interface:f[0]}
   bestMetric=metric
  }
 }
 return chosen
}
func parseLinuxIPv6Route(text string)GatewayInfo {
 var chosen GatewayInfo
 bestMetric:=uint64(^uint32(0))
 for _,line:=range strings.Split(text,"\n") {
  f:=strings.Fields(line)
  if len(f)<10||f[0]!=strings.Repeat("0",32)||f[1]!="00"||f[2]!=strings.Repeat("0",32)||f[3]!="00" {continue}
  flags,err1:=strconv.ParseUint(f[8],16,32)
  metric,err2:=strconv.ParseUint(f[5],16,32)
  ipBytes,err3:=hex.DecodeString(f[4])
  if err1!=nil||err2!=nil||err3!=nil||len(ipBytes)!=16||(flags&0x3)!=0x3{continue}
  if metric<bestMetric {
   chosen=GatewayInfo{Family:"IPv6",Gateway:net.IP(ipBytes).String(),Interface:f[9]}
   bestMetric=metric
  }
 }
 return chosen
}
func parseRouteGet(text,family string)GatewayInfo {
 g:=GatewayInfo{Family:family}
 for _,line:=range strings.Split(text,"\n") {
  key,val,ok:=strings.Cut(strings.TrimSpace(line),":")
  if !ok {continue}
  switch strings.TrimSpace(key){
  case "gateway":g.Gateway=strings.TrimSpace(val)
  case "interface":g.Interface=strings.TrimSpace(val)
  }
 }
 if ip:=net.ParseIP(strings.Split(g.Gateway,"%")[0]);ip==nil{return GatewayInfo{}}
 return g
}
func defaultGateways()([]GatewayInfo,[]string){
 results:=[]GatewayInfo{}
 notes:=[]string{}
 if runtime.GOOS=="linux" {
  for _,table:=range []struct{path string; parse func(string)GatewayInfo}{
   {"/proc/net/route",parseLinuxRoute},{"/proc/net/ipv6_route",parseLinuxIPv6Route},
  }{
   raw,err:=os.ReadFile(table.path)
   if err!=nil {notes=append(notes,filepath.Base(table.path)+": "+err.Error());continue}
   g:=table.parse(string(raw))
   if g.Gateway!="" {results=append(results,g)}
  }
 } else if runtime.GOOS=="darwin" {
  for _,kind:=range []struct{args []string;family string}{
   {[]string{"-n","get","default"},"IPv4"},
   {[]string{"-n","get","-inet6","default"},"IPv6"},
  } {
   ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
   out,err:=exec.CommandContext(ctx,"route",kind.args...).Output()
   cancel()
   if err!=nil {continue}
   if g:=parseRouteGet(string(out),kind.family);g.Gateway!="" {results=append(results,g)}
  }
 }else {
  notes=append(notes,"Default gateway detection unsupported on "+runtime.GOOS)
 }
 return results,notes
}
func preferredLocalIP()string{
 for _,network:=range []string{"udp4","udp6"} {
  dest:="8.8.8.8:53"
  if network=="udp6"{dest="[2001:4860:4860::8888]:53"}
  conn,err:=net.DialTimeout(network,dest,time.Second)
  if err!=nil{continue}
  addr,ok:=conn.LocalAddr().(*net.UDPAddr)
  conn.Close()
  if ok&&addr.IP!=nil&&!addr.IP.IsLoopback() {return addr.IP.String()}
 }
 return ""
}
func inspectLocal(client *http.Client,timeout time.Duration,whoisOnly bool)LocalReport {
 report:=LocalReport{Interfaces:[]InterfaceInfo{},Gateways:[]GatewayInfo{}}
 report.Hostname,_=os.Hostname()
 report.LocalIP=preferredLocalIP()
 interfaces,err:=net.Interfaces()
 if err!=nil {report.Warnings=append(report.Warnings,err.Error())}
 for _,iface:=range interfaces{
  if iface.Flags&net.FlagUp==0||iface.Flags&net.FlagLoopback!=0{continue}
  addrs,err:=iface.Addrs()
  if err!=nil {report.Warnings=append(report.Warnings,iface.Name+": "+err.Error());continue}
  item:=InterfaceInfo{Name:iface.Name,Flags:iface.Flags.String(),Addresses:[]string{}}
  for _,addr:=range addrs {item.Addresses=append(item.Addresses,addr.String())}
  if len(item.Addresses)>0 {report.Interfaces=append(report.Interfaces,item)}
 }
 gateways,errNotes:=defaultGateways()
 report.Gateways=gateways
 report.Warnings=append(report.Warnings,errNotes...)
 public,err:=publicIP(client,timeout)
 if err!=nil {report.Warnings=append(report.Warnings,"public IP: "+err.Error());return report}
 report.PublicIP=public
 r:=lookup(client,public,timeout,whoisOnly)
 report.Public=&r
 return report
}
// Main network view intentionally hides macOS discovery interfaces and
// virtual bridges unless -all is specified. JSON always includes everything.
func primaryInterfaces(r LocalReport) []InterfaceInfo {
 selected:=map[string]bool{}
 for _,gw:=range r.Gateways {if gw.Interface!="" {selected[gw.Interface]=true}}
 if r.LocalIP!="" {
  for _,iface:=range r.Interfaces {
   for _,address:=range iface.Addresses {
    host,_,err:=net.ParseCIDR(address)
    if err==nil && host.String()==r.LocalIP {selected[iface.Name]=true}
   }
  }
 }
 result:=[]InterfaceInfo{}
 for _,iface:=range r.Interfaces {
  if selected[iface.Name] {result=append(result,iface)}
 }
 return result
}
func formatLocal(r LocalReport,lang string,all,whoisOnly bool)string {
 var b strings.Builder
 fmt.Fprintf(&b,"NetKit  ·  %s\n",translate(lang,"networkOverview"))
 fmt.Fprintf(&b,"────────────────────────────────────────\n")
 fmt.Fprintf(&b,"  %-14s %s\n",translate(lang,"host"),cleanDisplay(r.Hostname))
 fmt.Fprintf(&b,"  %-14s %s\n",translate(lang,"localIP"),cleanDisplay(r.LocalIP))
 fmt.Fprintf(&b,"\n%s\n",translate(lang,"interfaces"))
 interfaces:=primaryInterfaces(r)
 if all {interfaces=r.Interfaces}
 for _,iface:=range interfaces {
  fmt.Fprintf(&b,"  %-12s %s\n",iface.Name,strings.Join(iface.Addresses,", "))
 }
 if len(interfaces)==0 {fmt.Fprintf(&b,"  %s\n",translate(lang,"unavailable"))}
 if !all && len(r.Interfaces)>len(interfaces) {
  fmt.Fprintf(&b,"  %s\n",fmt.Sprintf(translate(lang,"hiddenInterfaces"),len(r.Interfaces)-len(interfaces)))
 }
 fmt.Fprintf(&b,"\n%s\n",translate(lang,"gateways"))
 if len(r.Gateways)==0 {fmt.Fprintf(&b,"  %s\n",translate(lang,"unavailableGW"))}
 for _,gw:=range r.Gateways {
  fmt.Fprintf(&b,"  %-6s %s",gw.Family,gw.Gateway)
  if gw.Interface!="" {fmt.Fprintf(&b," (%s)",gw.Interface)}
  b.WriteByte('\n')
 }
 fmt.Fprintf(&b,"\n%s\n",translate(lang,"publicDetail"))
 fmt.Fprintf(&b,"  %-14s %s\n",translate(lang,"publicIP"),cleanDisplay(r.PublicIP))
 if r.Public!=nil {
  fmt.Fprintf(&b,"  %s\n",compactLine(*r.Public,whoisOnly,lang))
 }
 if all && r.Public!=nil {
  // The full WHOIS and API payloads are printed separately, after the
  // readable network summary.
  fmt.Fprintf(&b,"\n")
 }
 return b.String()
}
func printLocal(r LocalReport,lang string,all,whoisOnly bool) {
 fmt.Print(formatLocal(r,lang,all,whoisOnly))
 if all && r.Public!=nil {printResult(*r.Public,true,whoisOnly,lang)}
 for _,warning:=range r.Warnings {fmt.Fprintln(os.Stderr,translate(lang,"warnings")+": "+warning)}
}
