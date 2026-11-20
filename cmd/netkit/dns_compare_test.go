package main

import (
 "context"
 "net"
 "reflect"
 "testing"
 "time"
)

func TestDNSSortedUnique(t *testing.T){
 input:=[]string{"8.8.8.8","1.1.1.1","8.8.8.8"}
 want:=[]string{"1.1.1.1","8.8.8.8"}
 if got:=uniqueSorted(input);!reflect.DeepEqual(got,want){t.Fatalf("got %v want %v",got,want)}
}
func TestDNSCompareResolverConfiguration(t *testing.T){
 if newDNSResolver("")!=net.DefaultResolver {t.Fatal("system lookup should preserve default resolver")}
 custom:=newDNSResolver("1.1.1.1:53")
 if !custom.PreferGo||custom.Dial==nil{t.Fatal("missing custom resolver dial")}
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
 defer cancel()
 _,err:=custom.Dial(ctx,"invalid-network","ignored")
 if err==nil{t.Fatal("expected invalid network error")}
}
func TestDNSErrorIsolation(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 result:=lookupDNSWithResolver(ctx,newDNSResolver("1.1.1.1:53"),"example.com")
 if result.Error=="" {t.Fatal("cancelled lookup should report an error")}
}
