package main

import (
 "strings"
 "testing"
 "reflect"
 "net"
 "net/http"
 "time"
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

func TestLocalization(t *testing.T) {
 if got:=countryName("zh","US");got!="美国" {t.Fatalf("zh US = %s",got)}
 if got:=countryName("en","US");got!="US" {t.Fatalf("en US = %s",got)}
 if got:=countryName("zh","ZZ");got!="ZZ" {t.Fatalf("unknown country must remain unchanged: %s",got)}
 if translate("zh","region")!="地区"||translate("en","region")!="Region" {t.Fatal("region translation")}
}
func TestCompactLineLanguages(t *testing.T) {
 hosting:=true
 r:=Result{IP:"8.8.8.8",Summary:Summary{
  Country:"US",ASN:"AS15169",Organization:"Google LLC",Hosting:&hosting,
  Agreements:map[string]Agreement{"region":{Value:"California",Agree:2,Reported:3,Alternatives:map[string][]string{"Virginia":{"ipinfo.io"}}}},
 },Sources:[]Source{{Name:"ip-api.com"},{Name:"ipwho.is"},{Name:"ipinfo.io",Error:"HTTP 429"},{Name:"api.ip.sb"}},
 Whois:Registry{Servers:[]string{"whois.iana.org","whois.arin.net"},CIDR:"8.8.8.0/24"}}
 zh:=compactLine(r,false,"zh")
 en:=compactLine(r,false,"en")
 if !strings.Contains(zh,"美国")||!strings.Contains(zh,"机房: 是")||!strings.Contains(zh,"数据源: 3/4") {t.Errorf("zh: %s",zh)}
 if !strings.Contains(en,"US")||!strings.Contains(en,"Hosting: Yes")||!strings.Contains(en,"Sources: 3/4") {t.Errorf("en: %s",en)}
 if strings.Contains(zh,"Difference/issue") {t.Errorf("old warning label: %s",zh)}
}

func TestIPScopes(t *testing.T) {
 cases:=[]struct{ip,scope string}{
  {"192.168.1.1","private"},{"10.0.0.2","private"},{"172.16.2.1","private"},
  {"100.64.1.1","shared"},{"127.0.0.1","loopback"},
  {"169.254.5.1","linklocal"},{"::1","loopback"},
  {"fe80::1","linklocal"},{"fc00::1","private"},
  {"192.0.2.1","documentation"},{"198.51.100.5","documentation"},{"203.0.113.1","documentation"},
  {"2001:db8::1","documentation"},{"198.18.1.1","benchmark"},
  {"8.8.8.8","public"},{"2606:4700:4700::1111","public"},
 }
 for _,tc:=range cases {
  got:=ipScope(net.ParseIP(tc.ip))
  if got!=tc.scope {t.Errorf("%s got %q want %q",tc.ip,got,tc.scope)}
 }
}
func TestLocalIPSkipsRemoteLookups(t *testing.T) {
 r:=lookup(&http.Client{}, "192.168.1.1",time.Nanosecond,false)
 if r.Scope!="private"||len(r.Sources)!=0||len(r.Whois.Servers)!=0 {t.Fatalf("unexpected external source: %+v",r)}
 if !strings.Contains(compactLine(r,false,"zh"),"私有内网 IP") {t.Fatalf("unexpected compact: %s",compactLine(r,false,"zh"))}
 if strings.Contains(compactLine(r,false,"zh"),"WHOIS:") {t.Fatal("should not claim WHOIS on private addresses")}
}
func TestLinuxDefaultRouteParser(t *testing.T) {
 table:="Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"+
  "eth0 00000000 0101A8C0 0003 0 0 10 00000000 0 0 0\n"+
  "wlan0 00000000 0102000A 0003 0 0 30 00000000 0 0 0\n"
 got:=parseLinuxRoute(table)
 if got.Gateway!="192.168.1.1"||got.Interface!="eth0" {t.Fatalf("unexpected route: %+v",got)}
}
func TestRouteGetParser(t *testing.T) {
 r:=parseRouteGet("route to: default\ngateway: 192.168.0.254\ninterface: en0\n","IPv4")
 if r.Gateway!="192.168.0.254"||r.Interface!="en0" {t.Fatalf("unexpected route: %+v",r)}
}

func TestDefaultCommandArgs(t *testing.T) {
 tests:=[]struct{in,want []string}{
  {[]string{"netkit"},[]string{"netkit","ip"}},
  {[]string{"netkit","ip"},[]string{"netkit","ip"}},
  {[]string{"netkit","-h"},[]string{"netkit","-h"}},
  {[]string{"netkit","dns"},[]string{"netkit","dns"}},
 }
 for _,tt:=range tests {
  got:=defaultCommandArgs(append([]string(nil),tt.in...))
  if !reflect.DeepEqual(got,tt.want) {t.Errorf("%v -> %v (want %v)",tt.in,got,tt.want)}
 }
}

func TestPrimaryInterfaces(t *testing.T) {
 r:=LocalReport{
  LocalIP:"192.168.31.158",
  Gateways:[]GatewayInfo{{Family:"IPv4",Gateway:"192.168.31.1",Interface:"en0"}},
  Interfaces:[]InterfaceInfo{
   {Name:"en0",Addresses:[]string{"192.168.31.158/24","fe80::1/64"}},
   {Name:"utun5",Addresses:[]string{"100.115.25.1/32"}},
   {Name:"bridge100",Addresses:[]string{"192.168.139.3/23"}},
  },
 }
 filtered:=primaryInterfaces(r)
 if len(filtered)!=1||filtered[0].Name!="en0" {t.Fatalf("unexpected primary interfaces: %+v",filtered)}
 output:=formatLocal(r,"zh",false,false)
 if !strings.Contains(output,"192.168.31.1")||!strings.Contains(output,"已隐藏 2 个其他接口") {t.Fatalf("overview: %s",output)}
 if strings.Contains(output,"bridge100")||strings.Contains(output,"utun5") {t.Fatalf("virtual interface leaked into overview: %s",output)}
 full:=formatLocal(r,"zh",true,false)
 if !strings.Contains(full,"bridge100")||!strings.Contains(full,"utun5") {t.Fatalf("missing full list: %s",full)}
 english:=formatLocal(r,"en",false,false)
 if !strings.Contains(english,"Local network overview") {t.Fatalf("english output: %s",english)}
}
func TestPrimaryInterfaceFromLocalIP(t *testing.T) {
 r:=LocalReport{
  LocalIP:"10.7.0.2",
  Interfaces:[]InterfaceInfo{
   {Name:"en0",Addresses:[]string{"192.168.31.158/24"}},
   {Name:"utun6",Addresses:[]string{"10.7.0.2/24"}},
  },
 }
 filtered:=primaryInterfaces(r)
 if len(filtered)!=1||filtered[0].Name!="utun6" {t.Fatalf("unexpected selected interface: %+v",filtered)}
}

func TestLocationCandidatesKeepPairs(t *testing.T) {
 sources:=[]Source{
  {Name:"ip-api.com",Data:map[string]any{"regionName":"东京","city":"新宿"}},
  {Name:"ipwho.is",Data:map[string]any{"region":"千叶县","city":"千叶"}},
  {Name:"ipinfo.io",Data:map[string]any{"region":"东京","city":"新宿"}},
  {Name:"api.ip.sb",Error:"HTTP 429"},
 }
 loc:=collectLocations(sources)
 if len(loc)!=2 {t.Fatalf("expected 2 paired locations: %+v",loc)}
 if loc[0].Region!="东京"||loc[0].City!="新宿"||len(loc[0].Sources)!=2 {t.Fatalf("unexpected majority: %+v",loc)}
 if loc[1].Region!="千叶县"||loc[1].City!="千叶" {t.Fatalf("unexpected alternative: %+v",loc)}
 result:=Result{IP:"8.8.8.8",Summary:aggregate(sources,Registry{}),Sources:sources}
 line:=compactLine(result,false,"zh")
 if !strings.Contains(line,"地点候选: 东京/新宿、千叶县/千叶") {t.Fatalf("missing paired locations: %s",line)}
 if strings.Contains(line,"GeoIP 差异: 地区,城市") {t.Fatalf("redundant mismatch: %s",line)}
}
func TestLocationCandidatesMissingFields(t *testing.T){
 loc:=collectLocations([]Source{
  {Name:"ip-api.com",Data:map[string]any{"regionName":"California"}},
  {Name:"ipwho.is",Data:map[string]any{"city":"Tokyo"}},
  {Name:"ipinfo.io",Data:map[string]any{"region":"Tokyo","city":"Tokyo"}},
 })
 labels:=locationLabels(loc)
 if strings.Join(labels,",")!="California,Tokyo,Tokyo" {t.Fatalf("unexpected labels: %v",labels)}
}
