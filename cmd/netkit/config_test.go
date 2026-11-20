package main

import (
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "runtime"
 "strings"
 "testing"
 "time"
)

func configTestHome(t *testing.T)string{
 t.Helper()
 home:=t.TempDir()
 t.Setenv("HOME",home)
 t.Setenv("NETKIT_AI_API_KEY","")
 t.Setenv("NETKIT_AI_MODEL","")
 t.Setenv("NETKIT_AI_BASE_URL","")
 t.Setenv("NETKIT_AI_TIMEOUT","")
 // Clear overrides using Unsetenv so absence and empty are distinguishable.
 for _,name:=range []string{"NETKIT_AI_API_KEY","NETKIT_AI_MODEL","NETKIT_AI_BASE_URL","NETKIT_AI_TIMEOUT"}{os.Unsetenv(name)}
 return home
}
func writeConfigFixture(t *testing.T,content string){
 t.Helper()
 path,err:=localConfigPath()
 if err!=nil{t.Fatal(err)}
 if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(path,[]byte(content),0600);err!=nil{t.Fatal(err)}
}
func TestConfigInitFileAndNoSecret(t *testing.T){
 configTestHome(t)
 path,err:=initializeLocalConfig()
 if err!=nil{t.Fatal(err)}
 info,err:=os.Stat(path)
 if err!=nil{t.Fatal(err)}
 if info.Mode().Perm()!=0600{t.Fatalf("config permissions %s",info.Mode())}
 cfg,exists,err:=readLocalConfig()
 if err!=nil||!exists{t.Fatalf("init did not read: %v",err)}
 if cfg.AI.Credential.Service!="netkit.ai"||cfg.AI.Credential.Account!="openai"{t.Fatalf("wrong defaults: %+v",cfg)}
 if runtime.GOOS=="darwin"&&cfg.AI.Credential.Source!="keychain"{t.Fatal("macOS must default to Keychain")}
 if runtime.GOOS!="darwin"&&cfg.AI.Credential.Source!="env"{t.Fatal("other platforms must use env")}
 data,err:=os.ReadFile(path)
 if err!=nil{t.Fatal(err)}
 if strings.Contains(string(data),"api_key")||strings.Contains(string(data),"password"){t.Fatal("secret field present in template")}
 if _,err:=initializeLocalConfig();err==nil{t.Fatal("config init overwrote existing file")}
}
func TestConfigRejectsPlainSecretsAndSymlinks(t *testing.T){
 home:=configTestHome(t)
 writeConfigFixture(t,`{"ai":{"api_key":"sk-test-secret"}}`)
 if _,_,err:=readLocalConfig();err==nil{t.Fatal("plaintext key accepted")}
 path,_:=localConfigPath()
 if err:=os.Remove(path);err!=nil{t.Fatal(err)}
 target:=filepath.Join(home,"original.json")
 if err:=os.WriteFile(target,[]byte(`{}`),0600);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(target,path);err!=nil{t.Fatal(err)}
 if _,_,err:=readLocalConfig();err==nil{t.Fatal("symlink accepted")}
}
func TestConfigPrecedenceAndKeychainNotExposed(t *testing.T){
 configTestHome(t)
 cfg:=defaultLocalConfig()
 cfg.AI.BaseURL="https://api.example.org/v1"
 cfg.AI.Model="config-model"
 cfg.AI.Credential.Source="keychain"
 cfg.AI.Credential.Service="netkit.ai"
 cfg.AI.Credential.Account="newapi"
 data,_:=json.Marshal(cfg)
 writeConfigFixture(t,string(data))
 calls:=0
 reader:=func(service,account string)(string,error){
  calls++
  if service!="netkit.ai"||account!="newapi"{t.Fatalf("bad Keychain identity: %s/%s",service,account)}
  return "top-secret-key",nil
 }
 settings,err:=loadAISettingsWithReader(reader)
 if err!=nil||settings.APIKey!="top-secret-key"||settings.Model!="config-model"||calls!=1{t.Fatalf("keychain load: %#v, %v",settings,err)}
 t.Setenv("NETKIT_AI_API_KEY","env-secret")
 t.Setenv("NETKIT_AI_MODEL","overridden-model")
 t.Setenv("NETKIT_AI_BASE_URL","https://api.openai.com/v1")
 t.Setenv("NETKIT_AI_TIMEOUT","17s")
 settings,err=loadAISettingsWithReader(reader)
 if err!=nil||settings.APIKey!="env-secret"||settings.Model!="overridden-model"||settings.Timeout!=17*time.Second||calls!=1{
  t.Fatalf("env override: %#v, %v",settings,err)
 }
 if settings.BaseURL!="https://api.openai.com/v1"{t.Fatal("base URL override lost")}
}
func TestConfigNoKeychainForLocalOllama(t *testing.T){
 configTestHome(t)
 cfg:=defaultLocalConfig()
 cfg.AI.BaseURL="http://127.0.0.1:11434/v1"
 cfg.AI.Model="qwen3:8b"
 cfg.AI.Credential.Source="keychain"
 data,_:=json.Marshal(cfg)
 writeConfigFixture(t,string(data))
 settings,err:=loadAISettingsWithReader(func(string,string)(string,error){t.Fatal("local AI must not read Keychain");return "",nil})
 if err!=nil||settings.APIKey!=""||settings.Model!="qwen3:8b"{t.Fatalf("local model: %+v %v",settings,err)}
}
func TestConfigErrorsDoNotExposeSecrets(t *testing.T){
 configTestHome(t)
 cfg:=defaultLocalConfig()
 cfg.AI.Model="model"
 cfg.AI.Credential.Source="keychain"
 data,_:=json.Marshal(cfg)
 writeConfigFixture(t,string(data))
 settings,err:=loadAISettingsWithReader(func(string,string)(string,error){return "",errors.New("secret-sentinel")})
 if err==nil||settings.APIKey!=""{t.Fatalf("expected safe lookup failure: %v",err)}
 // A real macOS implementation replaces OS error details with a safe error.
 // The injected reader must not leak its diagnostic text to the user.
 if strings.Contains(err.Error(),"secret-sentinel")||!strings.Contains(err.Error(),"Keychain credential unavailable"){
  t.Fatalf("credential error leaked internal details: %v",err)
 }
}
func TestConfigValidation(t *testing.T){
 c:=defaultLocalConfig()
 c.AI.Credential.Source="unknown"
 if validateLocalConfig(c)==nil{t.Fatal("invalid credential source allowed")}
 c=defaultLocalConfig()
 c.AI.Credential.Account="-bad"
 if validateLocalConfig(c)==nil{t.Fatal("invalid account accepted")}
 c=defaultLocalConfig()
 c.AI.Timeout="not-time"
 if validateLocalConfig(c)==nil{t.Fatal("bad timeout accepted")}
}
