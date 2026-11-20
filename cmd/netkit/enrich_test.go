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
