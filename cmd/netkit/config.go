package main

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "runtime"
 "time"
)

type CredentialConfig struct {
 Source string `json:"source"`
 Service string `json:"service,omitempty"`
 Account string `json:"account,omitempty"`
}
type LocalAIConfig struct {
 BaseURL string `json:"base_url"`
 Model string `json:"model"`
 Timeout string `json:"timeout"`
 Credential CredentialConfig `json:"credential"`
}
type LocalConfig struct {
 AI LocalAIConfig `json:"ai"`
}
var keychainIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,127}$`)

func defaultLocalConfig()LocalConfig{
 source:="env"
 if runtime.GOOS=="darwin"{source="keychain"}
 return LocalConfig{AI:LocalAIConfig{
  BaseURL:"https://api.openai.com/v1",
  Model:"",
  Timeout:"30s",
  Credential:CredentialConfig{Source:source,Service:"netkit.ai",Account:"openai"},
 }}
}
func localConfigPath()(string,error){
 home,err:=os.UserHomeDir()
 if err!=nil{return "",errors.New("cannot determine home directory")}
 return filepath.Join(home,".config","netkit","config.json"),nil
}
func readLocalConfig()(LocalConfig,bool,error){
 defaults:=defaultLocalConfig()
 path,err:=localConfigPath()
 if err!=nil{return defaults,false,err}
 info,err:=os.Lstat(path)
 if errors.Is(err,os.ErrNotExist){return defaults,false,nil}
 if err!=nil{return defaults,false,errors.New("cannot inspect NetKit configuration")}
 if !info.Mode().IsRegular(){return defaults,false,errors.New("NetKit configuration must be a regular file (not a symlink)")}
 if info.Size()>32*1024{return defaults,false,errors.New("NetKit configuration is too large")}
 raw,err:=os.ReadFile(path)
 if err!=nil{return defaults,false,errors.New("cannot read NetKit configuration")}
 if bytes.Contains(bytes.ToLower(raw),[]byte(`"api_key"`))||
  bytes.Contains(bytes.ToLower(raw),[]byte(`"password"`)){
  return defaults,false,errors.New("NetKit config must not contain API keys or passwords; use Keychain or environment variables")
 }
 var cfg LocalConfig
 decoder:=json.NewDecoder(bytes.NewReader(raw))
 decoder.DisallowUnknownFields()
 if err:=decoder.Decode(&cfg);err!=nil{return defaults,false,errors.New("invalid NetKit config JSON")}
 if decoder.Decode(new(any))!=io.EOF{return defaults,false,errors.New("NetKit config must contain one JSON object")}
 if cfg.AI.BaseURL==""{cfg.AI.BaseURL=defaults.AI.BaseURL}
 if cfg.AI.Timeout==""{cfg.AI.Timeout=defaults.AI.Timeout}
 if cfg.AI.Credential.Source==""{cfg.AI.Credential.Source=defaults.AI.Credential.Source}
 if cfg.AI.Credential.Service==""{cfg.AI.Credential.Service=defaults.AI.Credential.Service}
 if cfg.AI.Credential.Account==""{cfg.AI.Credential.Account=defaults.AI.Credential.Account}
 if err:=validateLocalConfig(cfg);err!=nil{return defaults,false,err}
 return cfg,true,nil
}
func validateLocalConfig(cfg LocalConfig)error{
 if cfg.AI.Credential.Source!="keychain"&&cfg.AI.Credential.Source!="env"{
  return errors.New("credential source must be keychain or env")
 }
 if !keychainIdentifier.MatchString(cfg.AI.Credential.Service)||!keychainIdentifier.MatchString(cfg.AI.Credential.Account){
  return errors.New("invalid Keychain service or account identifier")
 }
 if _,err:=time.ParseDuration(cfg.AI.Timeout);err!=nil{return errors.New("invalid config AI timeout")}
 if len(cfg.AI.Model)>128{return errors.New("AI model name is too long")}
 if _,_,err:=aiEndpoint(cfg.AI.BaseURL);err!=nil{return err}
 return nil
}
func initializeLocalConfig()(string,error){
 path,err:=localConfigPath()
 if err!=nil{return "",err}
 if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return "",errors.New("cannot create NetKit config directory")}
 data,err:=json.MarshalIndent(defaultLocalConfig(),"","  ")
 if err!=nil{return "",err}
 data=append(data,'\n')
 file,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if errors.Is(err,os.ErrExist){return "",errors.New("NetKit config already exists; refusing overwrite")}
 if err!=nil{return "",errors.New("cannot create NetKit config")}
 defer file.Close()
 if _,err:=file.Write(data);err!=nil{return "",errors.New("cannot write NetKit config")}
 return path,nil
}
func loadAISettings()(AISettings,error){
 cfg,_,err:=readLocalConfig()
 if err!=nil{return AISettings{},err}
 settings:=AISettings{BaseURL:cfg.AI.BaseURL,Model:cfg.AI.Model}
 settings.Timeout,err=time.ParseDuration(cfg.AI.Timeout)
 if err!=nil{return settings,errors.New("invalid configured timeout")}
 if v,ok:=os.LookupEnv("NETKIT_AI_BASE_URL");ok{settings.BaseURL=v}
 if v,ok:=os.LookupEnv("NETKIT_AI_MODEL");ok{settings.Model=v}
 if v,ok:=os.LookupEnv("NETKIT_AI_TIMEOUT");ok{
  settings.Timeout,err=time.ParseDuration(v)
  if err!=nil{return settings,errors.New("invalid NETKIT_AI_TIMEOUT")}
 }
 if v,ok:=os.LookupEnv("NETKIT_AI_API_KEY");ok{
  settings.APIKey=v
  return settings,nil // explicit env overrides Keychain without reading it
 }
 endpoint,loopback,err:=aiEndpoint(settings.BaseURL)
 if err!=nil{return settings,err}
 _=endpoint
 if loopback{return settings,nil} // local Ollama needs no key
 if cfg.AI.Credential.Source=="keychain"{
  key,err:=readKeychainSecret(cfg.AI.Credential.Service,cfg.AI.Credential.Account)
  if err!=nil{return settings,err}
  settings.APIKey=key
 }
 return settings,nil
}
func runConfig(args []string)error{
 if len(args)==0||args[0]=="-h"||args[0]=="--help"{
  fmt.Println("用法: netkit config init | show | ai-key set|status|delete")
  fmt.Println("配置文件: ~/.config/netkit/config.json（只保存非敏感设置）")
  fmt.Println("macOS API Key: 登录钥匙串；Linux/CI: NETKIT_AI_API_KEY 环境变量")
  return nil
 }
 switch args[0]{
 case "init":
  if len(args)!=1{return errors.New("usage: netkit config init")}
  path,err:=initializeLocalConfig()
  if err!=nil{return err}
  fmt.Println("Created:",path)
  return nil
 case "show":
  if len(args)!=1{return errors.New("usage: netkit config show")}
  cfg,exists,err:=readLocalConfig()
  if err!=nil{return err}
  path,_:=localConfigPath()
  fmt.Printf("Config: %s (exists: %t)\n",path,exists)
  fmt.Printf("AI endpoint: %s\nAI model: %s\nAI timeout: %s\nCredential source: %s\n",cfg.AI.BaseURL,cfg.AI.Model,cfg.AI.Timeout,cfg.AI.Credential.Source)
  fmt.Printf("Keychain item: %s / %s\n",cfg.AI.Credential.Service,cfg.AI.Credential.Account)
  fmt.Println("API Key value: never displayed")
  return nil
 case "ai-key":
  if len(args)!=2{return errors.New("usage: netkit config ai-key set|status|delete")}
  cfg,_,err:=readLocalConfig()
  if err!=nil{return err}
  service,account:=cfg.AI.Credential.Service,cfg.AI.Credential.Account
  switch args[1]{
  case "set":
   if err:=storeKeychainSecret(service,account);err!=nil{return err}
   fmt.Println("Keychain credential saved (secret not displayed)")
   return nil
  case "status":
   exists,err:=keychainSecretExists(service,account)
   if err!=nil{return err}
   if exists{fmt.Println("Keychain credential: present")}else{fmt.Println("Keychain credential: not found")}
   return nil
  case "delete":
   if err:=deleteKeychainSecret(service,account);err!=nil{return err}
   fmt.Println("Keychain credential deleted")
   return nil
  }
 }
 return errors.New("invalid config command (see netkit config --help)")
}
