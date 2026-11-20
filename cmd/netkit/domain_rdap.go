package main

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "net/http"
 "net/url"
 "strings"
 "time"
)

// DomainRegistration describes registry-level information, which is distinct
// from DNS records and may differ from the registrar's retail expiry date.
type DomainRegistration struct {
 Domain string `json:"domain,omitempty"`
 Registrar string `json:"registrar,omitempty"`
 RegistrarIANAID string `json:"registrar_iana_id,omitempty"`
 CreatedAt string `json:"created_at,omitempty"`
 UpdatedAt string `json:"updated_at,omitempty"`
 ExpiresAt string `json:"expires_at,omitempty"`
 Status []string `json:"status,omitempty"`
 RDAPURL string `json:"rdap_url,omitempty"`
 Error string `json:"error,omitempty"`
}

func domainBootstrapURL(raw []byte, domain string)(string,error){
 var bootstrap bootstrapData
 if err:=json.Unmarshal(raw,&bootstrap);err!=nil{return "",err}
 name:=strings.TrimSuffix(strings.ToLower(domain),".")
 best:=-1
 result:=""
 for _,service:=range bootstrap.Services{
  if len(service)!=2{continue}
  for _,suffix:=range service[0]{
   suffix=strings.TrimSuffix(strings.ToLower(strings.TrimSpace(suffix)),".")
   if suffix=="" || !(name==suffix||strings.HasSuffix(name,"."+suffix)){continue}
   for _,endpoint:=range service[1]{
    u,err:=url.Parse(endpoint)
    if err!=nil||u.Scheme!="https"||u.Hostname()==""||u.User!=nil||u.Fragment!=""||u.RawQuery!=""{continue}
    if len(suffix)>best {best=len(suffix);result=endpoint}
    break
   }
  }
 }
 if result==""{return "",errors.New("no matching HTTPS domain RDAP service")}
 return result,nil
}

func parseDomainRegistration(data map[string]any) DomainRegistration{
 r:=DomainRegistration{
  Domain:first(value(data,"ldhName"),value(data,"unicodeName")),
  Status:uniqueStrings(stringList(data["status"])),
 }
 for _,entry:=range anyList(data["events"]){
  event,ok:=entry.(map[string]any);if !ok{continue}
  action:=strings.ToLower(value(event,"eventAction"))
  date:=value(event,"eventDate")
  if date==""{continue}
  // Keep timestamps as supplied by RDAP (RFC3339, including timezone).
  switch action {
  case "registration":if r.CreatedAt==""{r.CreatedAt=date}
  case "expiration":if r.ExpiresAt==""{r.ExpiresAt=date}
  case "last changed":if r.UpdatedAt==""{r.UpdatedAt=date}
  }
 }
 var visit func(map[string]any,int)
 visit=func(entity map[string]any,depth int){
  if depth>8{return}
  if containsRole(stringList(entity["roles"]),"registrar"){
   name,_:=vcardIdentity(entity)
   if r.Registrar=="" {r.Registrar=name}
   for _,raw:=range anyList(entity["publicIds"]){
    id,ok:=raw.(map[string]any)
    if !ok{continue}
    if strings.EqualFold(value(id,"type"),"IANA Registrar ID")&&r.RegistrarIANAID==""{
     r.RegistrarIANAID=value(id,"identifier")
    }
   }
  }
  for _,raw:=range anyList(entity["entities"]){
   if child,ok:=raw.(map[string]any);ok{visit(child,depth+1)}
  }
 }
 for _,raw:=range anyList(data["entities"]){
  if entity,ok:=raw.(map[string]any);ok{visit(entity,0)}
 }
 return r
}

func fetchDomainRegistration(client *http.Client,domain string,timeout time.Duration)DomainRegistration{
 result:=DomainRegistration{}
 ctx,cancel:=context.WithTimeout(context.Background(),3*timeout)
 defer cancel()
 bootstrapURL:="https://data.iana.org/rdap/dns.json"
 raw,status,err:=getHTTP(ctx,client,bootstrapURL,"application/json")
 if err!=nil{result.Error=err.Error();return result}
 if status!=http.StatusOK{result.Error=fmt.Sprintf("IANA bootstrap HTTP %d",status);return result}
 base,err:=domainBootstrapURL(raw,domain)
 if err!=nil{result.Error=err.Error();return result}
 u,err:=url.Parse(base)
 if err!=nil{result.Error=err.Error();return result}
 // Query the given host, then its parents on 404: www.example.com is
 // generally not a registered domain. Never query the TLD alone.
 labels:=strings.Split(strings.TrimSuffix(strings.ToLower(domain),"."),".")
 for start:=0;start<len(labels)-1;start++{
  target:=strings.Join(labels[start:],".")
  u.Path=strings.TrimSuffix(u.Path,"/")+"/domain/"+target
  // Always start from the original base; never append to a prior lookup.
  baseURL,_:=url.Parse(base)
  baseURL.Path=strings.TrimSuffix(baseURL.Path,"/")+"/domain/"+target
  endpoint:=baseURL.String()
  result.RDAPURL=endpoint
  body,status,err:=getHTTP(ctx,client,endpoint,"application/rdap+json, application/json")
  if err!=nil{result.Error=err.Error();return result}
  if status==http.StatusNotFound {continue}
  if status!=http.StatusOK{result.Error=fmt.Sprintf("RDAP HTTP %d",status);return result}
  var data map[string]any
  if err:=json.Unmarshal(body,&data);err!=nil{result.Error=err.Error();return result}
  if !strings.EqualFold(value(data,"objectClassName"),"domain"){
   result.Error="unexpected RDAP object class";return result
  }
  parsed:=parseDomainRegistration(data)
  parsed.RDAPURL=endpoint
  if parsed.Domain==""{parsed.Domain=target}
  return parsed
 }
 result.Error="registered domain not found by RDAP"
 return result
}
