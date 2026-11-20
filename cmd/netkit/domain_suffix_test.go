package main

import (
 "reflect"
 "strings"
 "testing"
)

func TestPSLRegistrableDomains(t *testing.T){
 cases:=[]struct{name,registered string;targets []string}{
  {"baidu.com","baidu.com",[]string{"baidu.com","www.baidu.com"}},
  {"www.baidu.com","baidu.com",[]string{"www.baidu.com"}},
  {"example.com.cn","example.com.cn",[]string{"example.com.cn","www.example.com.cn"}},
  {"api.example.com.cn","example.com.cn",[]string{"api.example.com.cn"}},
  {"example.co.jp","example.co.jp",[]string{"example.co.jp","www.example.co.jp"}},
  {"api.example.co.jp","example.co.jp",[]string{"api.example.co.jp"}},
  {"example.co.uk","example.co.uk",[]string{"example.co.uk","www.example.co.uk"}},
  {"www.example.co.uk","example.co.uk",[]string{"www.example.co.uk"}},
  {"foo.blogspot.com","foo.blogspot.com",[]string{"foo.blogspot.com","www.foo.blogspot.com"}},
  {"bar.foo.blogspot.com","foo.blogspot.com",[]string{"bar.foo.blogspot.com"}},
  {"project.github.io","project.github.io",[]string{"project.github.io","www.project.github.io"}},
  {"www.ck","www.ck",[]string{"www.ck","www.www.ck"}},
  {"foo.ck","",[]string{"foo.ck"}},
  {"bar.foo.ck","bar.foo.ck",[]string{"bar.foo.ck","www.bar.foo.ck"}},
  {"city.kawasaki.jp","city.kawasaki.jp",[]string{"city.kawasaki.jp","www.city.kawasaki.jp"}},
  {"a.city.kawasaki.jp","city.kawasaki.jp",[]string{"a.city.kawasaki.jp"}},
  {"com.cn","",[]string{"com.cn"}},
  {"unknown.example.invalid","example.invalid",[]string{"unknown.example.invalid"}},
 }
 for _,tc:=range cases {
  if got:=registeredDomain(tc.name);got!=tc.registered{t.Errorf("registeredDomain(%s) = %q, want %q",tc.name,got,tc.registered)}
  if got:=domainTargets(tc.name);!reflect.DeepEqual(got,tc.targets){t.Errorf("domainTargets(%s) = %v, want %v",tc.name,got,tc.targets)}
 }
}
func TestSuffixRulesWildcardExceptionPrecedence(t *testing.T){
 rules:=parseSuffixRules("// note\ncom\nco.test\n*.wild.test\n!special.wild.test\n")
 for _,tc:=range []struct{name,want string}{
  {"example.com","example.com"},
  {"foo.co.test","foo.co.test"},
  {"bar.foo.co.test","foo.co.test"},
  {"foo.wild.test",""},
  {"bar.foo.wild.test","bar.foo.wild.test"},
  {"special.wild.test","special.wild.test"},
  {"bar.special.wild.test","special.wild.test"},
 }{
  if got:=registeredDomainWithRules(tc.name,rules);got!=tc.want{
   t.Errorf("%q: got %q want %q",tc.name,got,tc.want)
  }
 }
}
func TestEmbeddedPSLHasLicensingAndPrivateDomains(t *testing.T){
 if len(publicSuffixSource)<200000{t.Fatal("PSL snapshot unexpectedly small")}
 if !strings.Contains(publicSuffixSource,"Mozilla Public")||!strings.Contains(publicSuffixSource,"// ===BEGIN PRIVATE DOMAINS==="){
  t.Fatal("missing PSL license or private section")
 }
}
