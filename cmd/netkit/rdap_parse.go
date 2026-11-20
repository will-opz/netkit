package main

import (
 "strings"
)

// RDAP entity relationships are nested. The top-level network usually does
// not contain the registrant name or abuse email.
type RDAPContact struct {
 Handle string `json:"handle,omitempty"`
 Roles []string `json:"roles,omitempty"`
 Name string `json:"name,omitempty"`
 Emails []string `json:"emails,omitempty"`
}
func stringList(v any) []string {
 result:=[]string{}
 for _,item:=range anyList(v) {
  if text,ok:=item.(string);ok&&strings.TrimSpace(text)!="" {result=append(result,strings.TrimSpace(text))}
 }
 return result
}
func anyList(v any) []any {out,_:=v.([]any);return out}
func containsRole(roles []string,role string)bool {
 for _,r:=range roles {if strings.EqualFold(r,role){return true}}
 return false
}
func uniqueStrings(items []string)[]string {
 out:=[]string{}
 seen:=map[string]bool{}
 for _,s:=range items {
  k:=strings.ToLower(strings.TrimSpace(s))
  if k!=""&&!seen[k] {seen[k]=true;out=append(out,strings.TrimSpace(s))}
 }
 return out
}
func vcardIdentity(entity map[string]any)(string,[]string){
 card:=anyList(entity["vcardArray"])
 if len(card)<2 {return "",nil}
 props:=anyList(card[1])
 name:=""
 emails:=[]string{}
 for _,v:=range props {
  property:=anyList(v)
  if len(property)<4 {continue}
  key,ok:=property[0].(string)
  if !ok {continue}
  switch strings.ToLower(key) {
  case "fn","org":
   if name=="" {
    if value,ok:=property[3].(string);ok {name=strings.TrimSpace(value)}
    if vals,ok:=property[3].([]any);ok {
     for _,item:=range vals {if str,ok:=item.(string);ok&&str!="" {name=str;break}}
    }
   }
  case "email":
   if value,ok:=property[3].(string);ok&&strings.Contains(value,"@"){emails=append(emails,value)}
  }
 }
 return name,uniqueStrings(emails)
}
func parseRDAPNetwork(data map[string]any)RDAPInfo{
 result:=RDAPInfo{
  Name:value(data,"name"),Handle:value(data,"handle"),Country:value(data,"country"),
  StartAddress:value(data,"startAddress"),EndAddress:value(data,"endAddress"),
 }
 var visit func(map[string]any,int)
 visit=func(entity map[string]any,depth int){
  if depth>8||len(result.Contacts)>=128 {return}
  roles:=stringList(entity["roles"])
  name,emails:=vcardIdentity(entity)
  contact:=RDAPContact{Handle:value(entity,"handle"),Roles:roles,Name:name,Emails:emails}
  if contact.Name!=""||len(contact.Emails)>0 {
   result.Contacts=append(result.Contacts,contact)
  }
  if result.Organization==""&&(containsRole(roles,"registrant")||containsRole(roles,"administrative"))&&name!=""{
   result.Organization=name
  }
  if containsRole(roles,"abuse"){result.AbuseEmails=append(result.AbuseEmails,emails...)}
  for _,child:=range anyList(entity["entities"]){
   if nested,ok:=child.(map[string]any);ok {visit(nested,depth+1)}
  }
 }
 for _,entry:=range anyList(data["entities"]){
  if entity,ok:=entry.(map[string]any);ok {visit(entity,0)}
 }
 result.AbuseEmails=uniqueStrings(result.AbuseEmails)
 return result
}
