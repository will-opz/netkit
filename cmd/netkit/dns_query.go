package main

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/http"
 "net/url"
 "strings"
 "time"
)

// DNSQuery uses a public DNS-over-HTTPS JSON endpoint and therefore does
// not represent the OS resolver or an authoritative nameserver observation.
type DNSQueryRecord struct {
 Name string `json:"name"`
 Type string `json:"type"`
 TypeCode int `json:"type_code"`
 TTL uint32 `json:"ttl"`
 Data string `json:"data"`
}
type DNSQueryReport struct {
 Name string `json:"name"`
 Type string `json:"type"`
 Provider string `json:"provider"`
 Endpoint string `json:"endpoint"`
 Status string `json:"status"`
 RCODE int `json:"rcode"`
 Truncated bool `json:"truncated"`
 AuthenticData bool `json:"authentic_data"`
 CheckingDisabled bool `json:"checking_disabled"`
 Answers []DNSQueryRecord `json:"answers"`
 Authority []DNSQueryRecord `json:"authority"`
 DurationMS int64 `json:"duration_ms"`
 Error string `json:"error,omitempty"`
}
type dohAnswer struct {
 Name string `json:"name"`
 Type int `json:"type"`
 TTL uint32 `json:"TTL"`
 Data string `json:"data"`
}
type dohResponse struct {
 Status int `json:"Status"`
 TC bool `json:"TC"`
 AD bool `json:"AD"`
 CD bool `json:"CD"`
 Answer []dohAnswer `json:"Answer"`
 Authority []dohAnswer `json:"Authority"`
}

var supportedDNSTypes=map[string]int{
 "A":1,"NS":2,"CNAME":5,"SOA":6,"PTR":12,"MX":15,
 "TXT":16,"AAAA":28,"SRV":33,"CAA":257,
}
var dnsRCODENames=map[int]string{
 0:"NOERROR",1:"FORMERR",2:"SERVFAIL",3:"NXDOMAIN",
 4:"NOTIMP",5:"REFUSED",6:"YXDOMAIN",7:"YXRRSET",
 8:"NXRRSET",9:"NOTAUTH",10:"NOTZONE",
}
func dnsRCODEName(code int) string{
 if n,ok:=dnsRCODENames[code];ok{return n}
 return fmt.Sprintf("UNKNOWN(%d)",code)
}
func dnsTypeName(code int)string{
 for name,value:=range supportedDNSTypes{if value==code{return name}}
 return fmt.Sprintf("TYPE%d",code)
}
func convertDNSRecords(raw []dohAnswer)[]DNSQueryRecord{
 result:=make([]DNSQueryRecord,0,len(raw))
 for _,item:=range raw{
  result=append(result,DNSQueryRecord{
   Name:strings.TrimSuffix(item.Name,"."),
   Type:dnsTypeName(item.Type),TypeCode:item.Type,
   TTL:item.TTL,Data:item.Data,
  })
 }
 return result
}
func dohProviderEndpoint(provider string)(string,string,error){
 switch strings.ToLower(strings.TrimSpace(provider)){
 case "cloudflare","cf":
  return "Cloudflare","https://cloudflare-dns.com/dns-query",nil
 case "google":
  return "Google","https://dns.google/resolve",nil
 default:return "","",fmt.Errorf("unsupported DNS provider %q: choose cloudflare or google",provider)
 }
}
func performDNSQuery(ctx context.Context,client *http.Client,endpoint,provider,name,recordType string)(report DNSQueryReport){
 report=DNSQueryReport{
  Name:name,Type:recordType,Provider:provider,Endpoint:endpoint,
  Status:"UNKNOWN",RCODE:-1,
  Answers:[]DNSQueryRecord{},Authority:[]DNSQueryRecord{},
 }
 started:=time.Now()
 defer func(){report.DurationMS=time.Since(started).Milliseconds()}()
 u,err:=url.Parse(endpoint)
 if err!=nil {report.Error=err.Error();return report}
 q:=u.Query();q.Set("name",name);q.Set("type",recordType);u.RawQuery=q.Encode()
 req,err:=http.NewRequestWithContext(ctx,http.MethodGet,u.String(),nil)
 if err!=nil{report.Error=err.Error();return report}
 req.Header.Set("Accept","application/dns-json")
 req.Header.Set("User-Agent",agent)
 resp,err:=client.Do(req)
 if err!=nil{report.Error=err.Error();return report}
 defer resp.Body.Close()
 if resp.StatusCode!=http.StatusOK{
  report.Error=fmt.Sprintf("DoH HTTP %d",resp.StatusCode)
  return report
 }
 // No unbounded body read from untrusted DoH services.
 var payload dohResponse
 decoder:=json.NewDecoder(io.LimitReader(resp.Body,1<<20))
 if err:=decoder.Decode(&payload);err!=nil{report.Error="invalid DoH JSON: "+err.Error();return report}
 if payload.Status<0||payload.Status>4095{
  report.Error="invalid DNS RCODE";return report
 }
 report.RCODE=payload.Status
 report.Status=dnsRCODEName(payload.Status)
 report.Truncated=payload.TC
 report.AuthenticData=payload.AD
 report.CheckingDisabled=payload.CD
 report.Answers=convertDNSRecords(payload.Answer)
 report.Authority=convertDNSRecords(payload.Authority)
 return report
}
func executeDNSQuery(name,recordType,provider string,timeout time.Duration,client *http.Client)(DNSQueryReport,error){
 if !validDNSQueryName(name){return DNSQueryReport{},errors.New("invalid DNS query name")}
 kind:=strings.ToUpper(recordType)
 if _,ok:=supportedDNSTypes[kind];!ok{return DNSQueryReport{},fmt.Errorf("unsupported DNS record type %q",recordType)}
 display,endpoint,err:=dohProviderEndpoint(provider)
 if err!=nil{return DNSQueryReport{},err}
 ctx,cancel:=context.WithTimeout(context.Background(),timeout)
 defer cancel()
 result:=performDNSQuery(ctx,client,endpoint,display,strings.TrimSuffix(strings.ToLower(name),"."),kind)
 return result,nil
}
func validDNSQueryName(raw string)bool{
 if validDomain(raw){return true}
 // Permit underscore-prefixed service labels such as _dmarc, _sip._tcp.
 // Validate every label and do not accept whitespace, URLs or trailing junk.
 name:=strings.TrimSuffix(raw,".")
 if len(name)<3||len(name)>253||strings.ContainsAny(name,":/@\\ \\t\\r\\n"){return false}
 parts:=strings.Split(name,".")
 if len(parts)<3{return false}
 hasUnderscore:=false
 for i,label:=range parts{
  if label==""||len(label)>63{return false}
  if i==len(parts)-1 {
   if len(label)<2{return false}
  }
  if strings.HasPrefix(label,"_"){
   if i==len(parts)-1||len(label)<2{ return false }
   hasUnderscore=true
   label=label[1:]
  }
  if label[0]=='-'||label[len(label)-1]=='-'{return false}
  for _,c:=range label{
   if !(c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='-'){return false}
  }
 }
 if !hasUnderscore {return false}
 tld:=parts[len(parts)-1]
 digits:=true
 for _,c:=range tld{if c<'0'||c>'9'{digits=false;break}}
 return !digits
}
func dnsQueryHelp(){
 fmt.Println("用法: netkit dns query [-type A|AAAA|CNAME|MX|NS|TXT|SOA|CAA|SRV] [-provider cloudflare|google] [-timeout 5s] [--output text|json] [-lang zh|en] DOMAIN")
 fmt.Println("示例: netkit dns query -type SOA example.com")
 fmt.Println("      netkit dns query -type CAA -provider google example.com")
 fmt.Println("      netkit dns query -type TXT _dmarc.example.com")
 fmt.Println("HTTPS DoH 解析器的观察结果；不是系统 DNS、权威 DNS 或 DNSSEC 完整验证")
}
func runDNSQuery(args []string)error{
 if len(args)==0||args[0]=="-h"||args[0]=="--help"{dnsQueryHelp();return nil}
 fs:=flag.NewFlagSet("dns query",flag.ContinueOnError)
 recordType:=fs.String("type","A","DNS record type")
 provider:=fs.String("provider","cloudflare","DoH provider")
 timeout:=fs.Duration("timeout",5*time.Second,"query timeout")
 output:=fs.String("output","text","text or json")
 lang:=fs.String("lang","zh","zh or en")
 if err:=fs.Parse(args);err!=nil{return err}
 if *timeout<=0{return errors.New("-timeout must be positive")}
 if *lang!="zh"&&*lang!="en"{return errors.New("-lang must be zh or en")}
 format,err:=resolveOutputFormat(*output,false)
 if err!=nil{return err}
 if fs.NArg()!=1{return errors.New("expected one DNS name")}
 report,err:=executeDNSQuery(fs.Arg(0),*recordType,*provider,*timeout,&http.Client{Timeout:*timeout})
 if err!=nil{return err}
 if format=="json"{
  data,err:=json.MarshalIndent(report,"","  ")
  if err!=nil{return err}
  fmt.Println(string(data))
 }else{
  label:=func(zh,en string)string{if *lang=="en"{return en};return zh}
  fmt.Printf("%s: %s | %s %s | %s\n",label("DNS 查询","DNS query"),report.Name,report.Type,report.Provider,report.Status)
  fmt.Printf("  RCODE: %d (%s) | %s: %dms | AD: %t | CD: %t | TC: %t\n",
   report.RCODE,report.Status,label("耗时","Duration"),report.DurationMS,
   report.AuthenticData,report.CheckingDisabled,report.Truncated)
  for _,item:=range report.Answers{
   fmt.Printf("  %-6s TTL=%-6d %s\n",item.Type,item.TTL,item.Data)
  }
  if len(report.Authority)>0{
   fmt.Println(label("权威区段（响应中的 Authority）:","Authority section:"))
   for _,item:=range report.Authority{
    fmt.Printf("  %-6s TTL=%-6d %s\n",item.Type,item.TTL,item.Data)
   }
  }
  if report.Status=="NOERROR"&&len(report.Answers)==0{
   fmt.Println(label("无匹配记录（NOERROR / 无 Answer，不等同于 NXDOMAIN）","No answer records (NOERROR, not NXDOMAIN)"))
  }
  if report.Error!=""{fmt.Printf("%s: %s\n",label("查询错误","Query error"),report.Error)}
 }
 if report.Error!=""{return fmt.Errorf("DNS transport/response failure: %s",report.Error)}
 if report.RCODE!=0{return fmt.Errorf("DNS status %s",report.Status)}
 return nil
}
