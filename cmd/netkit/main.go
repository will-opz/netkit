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
 Summary Summary `json:"summary"`
 Sources []Source `json:"sources,omitempty"`
 Whois Registry `json:"whois"`
}

type provider struct { name, endpoint string }
var providers = []provider{
 {"ip-api.com", "http://ip-api.com/json/%s?lang=zh-CN&fields=66846719"},
 {"ipwho.is", "https://ipwho.is/%s"},
 {"ipinfo.io", "https://ipinfo.io/%s/json"},
 {"api.ip.sb", "https://api.ip.sb/geoip/%s"},
}

func main() {
 if len(os.Args)<2 || os.Args[1]=="-h" || os.Args[1]=="--help" || os.Args[1]=="help" {
  fmt.Println("NetKit: network diagnostics toolkit")
  fmt.Println("Usage: netkit ip [options] [IPv4|IPv6 ...]")
  fmt.Println("Commands:\n  ip    Multi-source IP geolocation and WHOIS lookup")
  fmt.Println("Run netkit ip -h for flags. With no IP, discover your public IP.")
  return
 }
 if os.Args[1]!="ip" {
  fmt.Fprintln(os.Stderr,"unknown command:",os.Args[1])
  fmt.Fprintln(os.Stderr,"Usage: netkit ip [options] [IPv4|IPv6 ...]")
  os.Exit(2)
 }
 os.Args=append([]string{os.Args[0]},os.Args[2:]...)
 all := flag.Bool("all", false, "print individual API responses and raw WHOIS")
 whoisOnly := flag.Bool("whois", false, "query native WHOIS only (TCP port 43)")
 jsonFlag := flag.Bool("json", false, "output JSON")
 timeout := flag.Duration("timeout", 5*time.Second, "per-request timeout")
 flag.Usage = func() {
  fmt.Fprintln(flag.CommandLine.Output(), "Usage: netkit ip [options] [IPv4|IPv6 ...]")
  fmt.Fprintln(flag.CommandLine.Output(), "With no IP, discover public IP via HTTPS fallback endpoints.")
  flag.PrintDefaults()
 }
 flag.Parse()
 if *timeout <= 0 { fmt.Fprintln(os.Stderr, "timeout must be positive"); os.Exit(2) }
 client := &http.Client{Transport: &http.Transport{Proxy:http.ProxyFromEnvironment, MaxIdleConns:16, IdleConnTimeout:30*time.Second}}
 ips := flag.Args()
 if len(ips)==0 {
  ip,err := publicIP(client,*timeout)
  if err!=nil {fmt.Fprintln(os.Stderr,"public IP discovery:",err);os.Exit(1)}
  ips=[]string{ip}
 }
 results:=make([]Result,0,len(ips))
 seen:=map[string]bool{}
 invalid:=false
 for _,input:=range ips {
  ip:=net.ParseIP(input)
  if ip==nil {fmt.Fprintln(os.Stderr,"invalid IP:",input);invalid=true;continue}
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
   if *all {printResult(r,true,*whoisOnly)} else {printCompact(r,*whoisOnly)}
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
func printResult(r Result,all,whoisOnly bool){
 fmt.Printf("\nIP: %s\n",r.IP)
 s:=r.Summary
 items:=[][2]string{
  {"Country",s.Country},{"Region",s.Region},{"City",s.City},{"ISP",s.ISP},
  {"Organization",s.Organization},{"ASN",s.ASN},{"Timezone",s.Timezone},
  {"WHOIS country",s.RegisteredCountry},{"Network",s.Network},{"Abuse email",s.AbuseEmail},
 }
 for _,pair:=range items {if pair[1]!="" {fmt.Printf("  %-18s %s\n",pair[0]+":",pair[1])}}
 if s.Hosting!=nil {fmt.Printf("  Hosting:            %v (provider observation)\n",*s.Hosting)}
 if s.Proxy!=nil {fmt.Printf("  Proxy:              %v (provider observation)\n",*s.Proxy)}
 keys:=make([]string,0,len(s.Agreements))
 for k:=range s.Agreements {keys=append(keys,k)}
 sort.Strings(keys)
 for _,k:=range keys {
  a:=s.Agreements[k]
  fmt.Printf("  %-18s %d/%d API source(s) agree\n",k+" agreement:",a.Agree,a.Reported)
  if len(a.Alternatives)>0 {fmt.Printf("    alternatives: %v\n",a.Alternatives)}
 }
 if len(r.Whois.Servers)>0 {fmt.Println("  WHOIS path:         "+strings.Join(r.Whois.Servers," -> "))}
 if r.Whois.Error!="" {fmt.Println("  WHOIS error:        "+r.Whois.Error)}
 if whoisOnly||all {
  if r.Whois.Raw!="" {fmt.Printf("\n[WHOIS raw]\n%s\n",r.Whois.Raw)}
 }
 if all&&!whoisOnly {
  for _,src:=range r.Sources {
   fmt.Printf("\n[%s] %dms %s\n",src.Name,src.DurationMS,src.URL)
   if src.Error!="" {fmt.Println("ERROR:",src.Error)}
   if src.Data!=nil {b,_:=json.MarshalIndent(src.Data,"","  ");fmt.Println(string(b))}
  }
 }
}

func printCompact(r Result,whoisOnly bool) {
 s:=r.Summary
 display:=func(x string)string {
  if strings.TrimSpace(x)=="" {return "-"}
  return strings.Join(strings.Fields(x)," ")
 }
 country:=s.Country
 if whoisOnly {country=s.RegisteredCountry}
 hosting:="Unknown"
 if s.Hosting!=nil {if *s.Hosting {hosting="Yes"} else {hosting="No"}}
 whoisStatus:="N/A"
 if len(r.Whois.Servers)>0 {
  whoisStatus="OK"
  if r.Whois.Error!="" {whoisStatus="Error"}
 } else if r.Whois.Error!="" {whoisStatus="Error"}
 if whoisOnly {
  fmt.Printf("%s | WHOIS: %s | %s | %s | %s | %s\n",
   r.IP,whoisStatus,display(country),display(s.ASN),display(s.Organization),display(s.Network))
  return
 }
 ok:=0
 for _,source:=range r.Sources {if source.Error=="" {ok++}}
 warnings:=[]string{}
 for _,key:=range []string{"country","region","city","asn"} {
  a,exists:=s.Agreements[key]
  if exists&&len(a.Alternatives)>0 {warnings=append(warnings,key)}
 }
 if ok==0 {warnings=append(warnings,"all GeoIP sources failed")}
 line:=fmt.Sprintf("%s | %s | %s | %s | Hosting: %s | Sources: %d/%d | WHOIS: %s",
  r.IP,display(country),display(s.ASN),display(s.Organization),hosting,ok,len(r.Sources),whoisStatus)
 if len(warnings)>0 {line+=" | ! Difference/issue: "+strings.Join(warnings,",")}
 fmt.Println(line)
}
