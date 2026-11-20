package main

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "net/http"
 "net/netip"
 "net/url"
 "sort"
 "strconv"
 "strings"
 "sync"
 "time"
)

// Enrichment results remain optional; no third-party dependencies.
type RDAPInfo struct {
 URL string `json:"url,omitempty"`
 Name string `json:"name,omitempty"`
 Handle string `json:"handle,omitempty"`
 Organization string `json:"organization,omitempty"`
 AbuseEmails []string `json:"abuse_emails,omitempty"`
 Contacts []RDAPContact `json:"contacts,omitempty"`
 Country string `json:"country,omitempty"`
 StartAddress string `json:"start_address,omitempty"`
 EndAddress string `json:"end_address,omitempty"`
 Error string `json:"error,omitempty"`
}
type PTRInfo struct {
 Hostnames []string `json:"hostnames,omitempty"`
 Error string `json:"error,omitempty"`
}
type BGPInfo struct {
 Prefix string `json:"prefix,omitempty"`
 ASNs []string `json:"asns,omitempty"`
 Source string `json:"source,omitempty"`
 Error string `json:"error,omitempty"`
}
type bootstrapData struct { Services [][][]string `json:"services"` }

func bootstrapRDAPURL(raw []byte, ip netip.Addr) (string,error) {
 var b bootstrapData
 if err:=json.Unmarshal(raw,&b);err!=nil{return "",err}
 best:=-1
 result:=""
 for _,service:=range b.Services{
  if len(service)!=2 {continue}
  for _,p:=range service[0]{
   prefix,err:=netip.ParsePrefix(p)
   if err!=nil||!prefix.Contains(ip)||prefix.Bits()<=best {continue}
   for _,base:=range service[1]{
    u,err:=url.Parse(base)
    if err==nil&&u.Scheme=="https"&&u.Hostname()!=""&&u.User==nil&&u.RawQuery==""&&u.Fragment==""{
     result=base;best=prefix.Bits();break
    }
   }
  }
 }
 if result=="" {return "",errors.New("no matching HTTPS RDAP bootstrap service")}
 return result,nil
}
func httpJSON(ctx context.Context,client *http.Client,endpoint string)(map[string]any,error){
 body,status,err:=getHTTP(ctx,client,endpoint,"application/rdap+json, application/json")
 if err!=nil{return nil,err}
 if status!=200{return nil,fmt.Errorf("HTTP %d",status)}
 var data map[string]any
 if err:=json.Unmarshal(body,&data);err!=nil{return nil,err}
 return data,nil
}
func fetchRDAP(client *http.Client,ip string,timeout time.Duration)RDAPInfo{
 r:=RDAPInfo{}
 parsed,err:=netip.ParseAddr(ip)
 if err!=nil{r.Error=err.Error();return r}
 endpoint:="https://data.iana.org/rdap/ipv4.json"
 if parsed.Is6(){endpoint="https://data.iana.org/rdap/ipv6.json"}
 ctx,cancel:=context.WithTimeout(context.Background(),2*timeout)
 defer cancel()
 raw,status,err:=getHTTP(ctx,client,endpoint,"application/json")
 if err!=nil {r.Error=err.Error();return r}
 if status!=200 {r.Error=fmt.Sprintf("bootstrap HTTP %d",status);return r}
 base,err:=bootstrapRDAPURL(raw,parsed)
 if err!=nil{r.Error=err.Error();return r}
 u,err:=url.Parse(base)
 if err!=nil{r.Error=err.Error();return r}
 u.Path=strings.TrimSuffix(u.Path,"/")+"/ip/"+ip
 u.RawQuery="";u.Fragment=""
 r.URL=u.String()
 data,err:=httpJSON(ctx,client,r.URL)
 if err!=nil{r.Error=err.Error();return r}
 if value(data,"objectClassName")!="ip network" {r.Error="unexpected RDAP object class";return r}
 parsedInfo:=parseRDAPNetwork(data)
 parsedInfo.URL=r.URL
 return parsedInfo
}
func lookupPTR(ip string,timeout time.Duration)PTRInfo{
 r:=PTRInfo{}
 ctx,cancel:=context.WithTimeout(context.Background(),timeout)
 defer cancel()
 names,err:=net.DefaultResolver.LookupAddr(ctx,ip)
 if err!=nil{r.Error=err.Error();return r}
 seen:=map[string]bool{}
 for _,name:=range names{
  name=strings.TrimSuffix(strings.TrimSpace(name),".")
  if name!=""&&!seen[name] {seen[name]=true;r.Hostnames=append(r.Hostnames,name)}
 }
 sort.Strings(r.Hostnames)
 return r
}
func parseBGP(data map[string]any)BGPInfo{
 r:=BGPInfo{Source:"RIPE RIS (network-info)"}
 if value(data,"status")!="ok" {r.Error="unexpected RIPEstat API status";return r}
 info:=object(data,"data")
 r.Prefix=value(info,"prefix")
 if list,ok:=info["asns"].([]any);ok {
  for _,item:=range list{
   switch v:=item.(type){
   case float64:r.ASNs=append(r.ASNs,normalizeASN(strconv.FormatFloat(v,'f',0,64)))
   case string:r.ASNs=append(r.ASNs,normalizeASN(v))
   }
  }
 }
 if r.Prefix=="" {r.Error="no routed prefix found"}
 return r
}
func fetchBGP(client *http.Client,ip string,timeout time.Duration)BGPInfo{
 ctx,cancel:=context.WithTimeout(context.Background(),timeout)
 defer cancel()
 endpoint:="https://stat.ripe.net/data/network-info/data.json?resource="+url.QueryEscape(ip)
 data,err:=httpJSON(ctx,client,endpoint)
 if err!=nil{return BGPInfo{Source:"RIPE RIS (network-info)",Error:err.Error()}}
 return parseBGP(data)
}
func enrichIP(client *http.Client,r *Result,timeout time.Duration,rdap,ptr,bgp bool){
 var wg sync.WaitGroup
 if rdap {wg.Add(1);go func(){defer wg.Done();x:=fetchRDAP(client,r.IP,timeout);r.RDAP=&x}()}
 if ptr {wg.Add(1);go func(){defer wg.Done();x:=lookupPTR(r.IP,timeout);r.PTR=&x}()}
 if bgp {wg.Add(1);go func(){defer wg.Done();x:=fetchBGP(client,r.IP,timeout);r.BGP=&x}()}
 wg.Wait()
}
func printEnrichment(r Result,lang string){
 if r.RDAP!=nil {
  x:=r.RDAP
  if x.Error!="" {fmt.Println("RDAP:",translate(lang,"error"),x.Error)
  }else{
   parts:=[]string{first(x.Organization,x.Name,x.Handle)}
   if x.Country!="" {parts=append(parts,countryName(lang,x.Country))}
   if x.StartAddress!=""&&x.EndAddress!="" {parts=append(parts,x.StartAddress+" - "+x.EndAddress)}
   if len(x.AbuseEmails)>0 {parts=append(parts,"Abuse: "+strings.Join(x.AbuseEmails,","))}
   fmt.Println("RDAP:",strings.Join(parts," | "))
  }
 }
 if r.PTR!=nil {
  x:=r.PTR
  if x.Error!="" {fmt.Println("PTR:",translate(lang,"error"),x.Error)
  }else{fmt.Println("PTR:",strings.Join(x.Hostnames,", "))}
 }
 if r.BGP!=nil {
  x:=r.BGP
  if x.Error!="" {fmt.Println("BGP:",translate(lang,"error"),x.Error)
  }else{fmt.Printf("BGP: %s | %s (%s)\n",x.Prefix,strings.Join(x.ASNs,","),x.Source)}
 }
}
