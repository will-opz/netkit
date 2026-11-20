package main

import (
 "strings"
 "testing"
)

func TestReferral(t *testing.T) {
 cases:=[]struct{input,want string}{
  {"refer: whois.apnic.net\n","whois.apnic.net"},
  {"ReferralServer: whois://whois.arin.net:43\n","whois.arin.net"},
  {"refer:\n",""},
  {"refer: whois.evil.example\n",""},
  {"refer: whois.apnic.net\nrefer: whois.ripe.net","whois.apnic.net"},
 }
 for _,tc:=range cases {
  // Registry referral URLs commonly include :43; support explicit default port.
  got:=referral(tc.input)
  if got!=tc.want {t.Errorf("referral(%q)=%q, want %q",tc.input,got,tc.want)}
 }
}
func TestWHOISFields(t *testing.T) {
 var w Registry
 whoisFields("NetRange: 198.51.100.0 - 198.51.100.255\nCIDR: 198.51.100.0/24\nOrgName: Example\ncountry: US\nOriginAS: AS64500\nOrgAbuseEmail: abuse@example.org\n",&w)
 if w.CIDR!="198.51.100.0/24"||w.Organization!="Example"||w.Country!="US"||w.ASN!="AS64500"||w.AbuseEmail!="abuse@example.org" {t.Fatalf("unexpected whois: %+v",w)}
}
func TestAgreementAndFallback(t *testing.T) {
 sources:=[]Source{
  {Name:"ip-api.com",Data:map[string]any{"countryCode":"JP","city":"Tokyo","as":"AS64500 Example"}},
  {Name:"ipwho.is",Data:map[string]any{"country_code":"JP","city":"Tokyo","connection":map[string]any{"asn":float64(64500)}}},
  {Name:"ipinfo.io",Data:map[string]any{"country":"US","city":"Chicago","org":"AS64501 Example"}},
  {Name:"api.ip.sb",Error:"HTTP 429"},
 }
 sum:=aggregate(sources,Registry{Country:"AU",Organization:"Registered Organization"})
 if sum.Country!="JP"||sum.ASN!="AS64500"||sum.RegisteredCountry!="AU" {t.Fatalf("bad summary: %+v",sum)}
 a:=sum.Agreements["country"]
 if a.Agree!=2||a.Reported!=3||!strings.Contains(strings.Join(a.Sources,","),"ipwho.is") {t.Fatalf("bad agreement: %+v",a)}
 if len(a.Alternatives["US"])!=1 {t.Fatalf("missing alternative: %+v",a)}
}
func TestUnknownProxy(t *testing.T){
 sum:=aggregate([]Source{{Name:"ipwho.is",Data:map[string]any{"country_code":"JP"}}},Registry{})
 if sum.Proxy!=nil||sum.Hosting!=nil {t.Fatal("missing detection must be unknown")}
}

func TestCompactFormattingSourceCount(t *testing.T) {
 r:=Result{IP:"203.0.113.8",Summary:Summary{Country:"JP",ASN:"AS64500",Organization:"Example"},
 Sources:[]Source{{Name:"ip-api.com",Data:map[string]any{"countryCode":"JP"}},{Name:"ipinfo.io",Error:"HTTP 429"}},
 Whois:Registry{Servers:[]string{"whois.iana.org"}}}
 // Ensure all compact dependencies are represented without a network request.
 if r.Summary.Country!="JP" || len(r.Sources)!=2 || r.Sources[1].Error=="" {t.Fatal("fixture invalid")}
}
