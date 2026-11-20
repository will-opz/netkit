package main

import (
 "encoding/json"
 "net/netip"
 "strings"
 "testing"
)

func TestRDAPBootstrapLongestPrefix(t *testing.T) {
 doc:=[]byte(`{"services":[[["8.0.0.0/8"],["https://rdap.example.net/"]],[["8.8.8.0/24"],["https://rdap.example.org/"]],[["8.8.8.0/25"],["http://insecure.example.org/"]]]}`)
 got,err:=bootstrapRDAPURL(doc,netip.MustParseAddr("8.8.8.8"))
 if err!=nil||got!="https://rdap.example.org/" {t.Fatalf("got %q, %v",got,err)}
 _,err=bootstrapRDAPURL(doc,netip.MustParseAddr("1.1.1.1"))
 if err==nil {t.Fatal("expected no match")}
}
func TestRDAPRejectsUnsafeEndpoint(t *testing.T){
 doc:=[]byte(`{"services":[[["8.0.0.0/8"],["http://example.com/","https://user:pass@example.com/"]]]}`)
 if _,err:=bootstrapRDAPURL(doc,netip.MustParseAddr("8.8.8.8"));err==nil {t.Fatal("expected reject")}
}
func TestParseBGP(t *testing.T){
 var input map[string]any
 if err:=json.Unmarshal([]byte(`{"status":"ok","data":{"prefix":"8.8.8.0/24","asns":[15169,64500]}}`),&input);err!=nil {t.Fatal(err)}
 got:=parseBGP(input)
 if got.Error!=""||got.Prefix!="8.8.8.0/24"||strings.Join(got.ASNs,",")!="AS15169,AS64500" {t.Fatalf("unexpected BGP: %+v",got)}
 if parseBGP(map[string]any{"status":"error"}).Error=="" {t.Fatal("expected API error")}
}

func TestNestedRDAPEntities(t *testing.T) {
 raw:=[]byte(`{
 "objectClassName":"ip network","name":"GOGL","handle":"NET-8-8-8-0-1",
 "startAddress":"8.8.8.0","endAddress":"8.8.8.255",
 "entities":[{
  "handle":"GOGL","roles":["registrant"],
  "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Google LLC"]]],
  "entities":[{"handle":"ABUSE5250","roles":["abuse"],
   "vcardArray":["vcard",[["fn",{},"text","Abuse"],["email",{},"text","network-abuse@google.com"]]]
  }]
 }]}`)
 var d map[string]any
 if err:=json.Unmarshal(raw,&d);err!=nil{t.Fatal(err)}
 got:=parseRDAPNetwork(d)
 if got.Organization!="Google LLC"||got.Name!="GOGL"||got.Country!="" {
  t.Fatalf("unexpected organization or inferred country: %+v",got)
 }
 if len(got.AbuseEmails)!=1||got.AbuseEmails[0]!="network-abuse@google.com"{
  t.Fatalf("missing abuse: %+v",got)
 }
 if len(got.Contacts)!=2 {t.Fatalf("contacts: %+v",got.Contacts)}
}
func TestRDAPContactRoleSafety(t *testing.T){
 var d map[string]any
 raw:=[]byte(`{"entities":[{"roles":["technical"],"vcardArray":["vcard",[["fn",{},"text","Technician"],["email",{},"text","tech@example.org"]]]},{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@example.org"],["email",{},"text","ABUSE@example.org"]]]}]}`)
 if err:=json.Unmarshal(raw,&d);err!=nil{t.Fatal(err)}
 got:=parseRDAPNetwork(d)
 if got.Organization!="" {t.Fatalf("technical contact must not be registrant: %+v",got)}
 if len(got.AbuseEmails)!=1 {t.Fatalf("abuse dedup failure: %+v",got)}
}
func TestRDAPIPv6Bootstrap(t *testing.T){
 doc:=[]byte(`{"services":[[["2001:4860::/32"],["https://rdap.example.org/"]]]}`)
 got,err:=bootstrapRDAPURL(doc,netip.MustParseAddr("2001:4860:4860::8888"))
 if err!=nil||got!="https://rdap.example.org/"{t.Fatalf("ipv6: %q %v",got,err)}
}
func TestPTRMissingNamesIsEmpty(t *testing.T){
 p:=PTRInfo{}
 if len(p.Hostnames)!=0||p.Error!="" {t.Fatalf("unexpected empty PTR: %+v",p)}
}
