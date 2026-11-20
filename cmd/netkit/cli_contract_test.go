package main

import (
 "encoding/json"
 "strings"
 "testing"
)

// Compatibility tests pin existing top-level JSON names while allowing
// additive optional fields. Do not make unrelated schema changes silently.
func TestCLIJSONContractCompatibility(t *testing.T){
 tests:=[]struct{
  name string
  value any
  required []string
  forbidden []string
 }{
  {"tcp",TCPReport{Host:"localhost",Port:443,Status:"connected",Attempts:[]TCPAttempt{{IP:"127.0.0.1",Connected:true}},AllIPs:true,SuccessCount:1},
   []string{"host","port","status","attempts","all_ips","success_count","dns_duration_ms","total_duration_ms"},
   []string{"dns_error","connected_ip"}},
  {"http",HTTPReport{Target:"https://example.com",Status:"ok",Hops:[]HTTPHop{{URL:"https://example.com",StatusCode:200,Phases:HTTPPhases{}}}},
   []string{"target","status","hops"},[]string{"error","https_downgrade"}},
  {"tls",TLSReport{Host:"example.com",Port:443,Connected:true,Verified:false,VerificationCode:"untrusted_authority",VerificationError:"unknown authority"},
   []string{"host","port","connected","verified","verification_code","verification_error","duration_ms"},
   []string{"connection_code","connection_error"}},
  {"dns query",DNSQueryReport{Name:"example.com",Type:"A",RCODE:3,Status:"NXDOMAIN",Answers:[]DNSQueryRecord{},Authority:[]DNSQueryRecord{}},
   []string{"name","type","rcode","status","answers","authority","duration_ms"},[]string{"error"}},
  {"dns compare",DNSCompareReport{Domain:"example.com",Resolvers:[]DNSResolverResult{},Different:false},
   []string{"domain","resolvers","different"},[]string{"detail"}},
 }
 for _,tc:=range tests {
  t.Run(tc.name,func(t *testing.T){
   encoded,err:=json.Marshal(tc.value)
   if err!=nil{t.Fatal(err)}
   var fields map[string]json.RawMessage
   if err:=json.Unmarshal(encoded,&fields);err!=nil{t.Fatal(err)}
   for _,key:=range tc.required{
    if _,ok:=fields[key];!ok{t.Errorf("required key %q absent in %s",key,encoded)}
   }
   for _,key:=range tc.forbidden{
    if _,ok:=fields[key];ok{t.Errorf("unexpected key %q in %s",key,encoded)}
   }
  })
 }
}
func TestCLIJSONAbsentHTTPPhasesAreNotZero(t *testing.T){
 encoded,err:=json.Marshal(HTTPHop{URL:"https://example.com",StatusCode:200,Phases:HTTPPhases{}})
 if err!=nil{t.Fatal(err)}
 if strings.Contains(string(encoded),"dns_ms")||strings.Contains(string(encoded),"tls_ms"){
  t.Fatalf("unobserved stages cannot be represented as zero timings: %s",encoded)
 }
}
func TestCLILocalhostTargets(t *testing.T){
 if !validTCPHost("localhost"){t.Fatal("TCP should allow local service diagnostic")}
 if !validTLSTarget("localhost"){t.Fatal("TLS should allow local service diagnostic")}
}
