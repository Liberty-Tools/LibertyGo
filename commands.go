package libertygo

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	DefaultPollInterval = 2 * time.Second
	DefaultShutdownTimeout = 10 * time.Second
	DefaultMaxSeenEvents = 1000
	maxReplyLength = 200
)

type CommandEvent struct {
	ID string `json:"id"`
	Type string `json:"type"`
	Command string `json:"command"`
	Argument string `json:"argument"`
	Args []string `json:"args"`
	UserID string `json:"userId"`
	ServerID string `json:"serverId"`
	Username string `json:"username"`
	Timestamp any `json:"timestamp,omitempty"`
	ReceivedAt any `json:"receivedAt,omitempty"`
	Raw map[string]any `json:"raw"`
}

type CommandStatus string
const (
	StatusIgnored CommandStatus="ignored"
	StatusRejected CommandStatus="rejected"
	StatusDuplicate CommandStatus="duplicate"
	StatusUnhandled CommandStatus="unhandled"
	StatusCooldown CommandStatus="cooldown"
	StatusHandled CommandStatus="handled"
	StatusFailed CommandStatus="failed"
)

type CommandResult struct { Status CommandStatus `json:"status"`; Reason string `json:"reason,omitempty"`; EventID string `json:"eventId,omitempty"`; Command string `json:"command,omitempty"`; Remaining time.Duration `json:"remaining,omitempty"`; Error error `json:"-"` }
type CommandHandler func(*CommandContext) error
type HandlerOptions struct { Cooldown time.Duration }
type commandRegistration struct { handler CommandHandler; cooldown time.Duration }

type CommandContext struct {
	Context context.Context
	Event CommandEvent
	Command string
	Argument string
	Args []string
	UserID string
	ServerID string
	router *CommandRouter
}
func (cc *CommandContext) Reply(ctx context.Context, message string) (CommandSummary,error) { return cc.router.reply(ctx,cc.Event,message) }
func (cc *CommandContext) Announce(ctx context.Context, message string) (CommandSummary,error) { if err:=validateMessage(message);err!=nil{return CommandSummary{},err}; return cc.router.client.SendPrivateServerCommand(ctx,[]string{":h "+sanitizeMessage(message)}) }

type CommandRouter struct {
	client *Client
	mu sync.Mutex
	handlers map[string]commandRegistration
	cooldowns map[string]time.Time
	seen map[string]bool
	seenOrder []string
	maxSeen int
	running bool
	cancel context.CancelFunc
	done chan struct{}
	Events chan CommandResult
	Errors chan error
}

func (c *Client) Commands() *CommandRouter { return NewCommandRouter(c,DefaultMaxSeenEvents) }
func NewCommandRouter(client *Client,maxSeen int) *CommandRouter { if maxSeen<1 {maxSeen=DefaultMaxSeenEvents};return &CommandRouter{client:client,handlers:map[string]commandRegistration{},cooldowns:map[string]time.Time{},seen:map[string]bool{},maxSeen:maxSeen,Events:make(chan CommandResult,32),Errors:make(chan error,16)} }

func normalizeCommandName(name string) string { name=strings.TrimSpace(name);name=strings.TrimPrefix(name,";");name=strings.ToLower(name);if name==""||strings.ContainsAny(name," \t\r\n"){return ""};return name }
func (r *CommandRouter) Register(name string,handler CommandHandler,options HandlerOptions) error { key:=normalizeCommandName(name);if key==""{return fmt.Errorf("command name must be non-empty and contain no whitespace")};if handler==nil{return fmt.Errorf("handler is required")};if options.Cooldown<0{return fmt.Errorf("cooldown must not be negative")};r.mu.Lock();defer r.mu.Unlock();r.handlers[key]=commandRegistration{handler,options.Cooldown};return nil }
func (r *CommandRouter) Remove(name string) bool { key:=normalizeCommandName(name);r.mu.Lock();defer r.mu.Unlock();if key==""{return false};if _,ok:=r.handlers[key];!ok{return false};delete(r.handlers,key);return true }

func (r *CommandRouter) Handle(ctx context.Context,input any) CommandResult {
	event,ok:=normalizeCommandEvent(input);if !ok{return CommandResult{Status:StatusIgnored,Reason:"unsupported_event"}}
	r.mu.Lock()
	if r.seen[event.ID] {r.mu.Unlock();return CommandResult{Status:StatusDuplicate,EventID:event.ID,Command:event.Command}}
	r.rememberLocked(event.ID)
	registration,found:=r.handlers[event.Command]
	if !found {result:=CommandResult{Status:StatusUnhandled,EventID:event.ID,Command:event.Command};r.mu.Unlock();r.emit(result);return result}
	cooldownKey:=event.Command+":"+event.UserID;if event.UserID==""{cooldownKey=event.Command+":unknown"}
	if until:=r.cooldowns[cooldownKey];until.After(time.Now()){result:=CommandResult{Status:StatusCooldown,EventID:event.ID,Command:event.Command,Remaining:time.Until(until)};r.mu.Unlock();r.emit(result);return result}
	if registration.cooldown>0 {r.cooldowns[cooldownKey]=time.Now().Add(registration.cooldown)}
	r.mu.Unlock()
	cc:=&CommandContext{Context:ctx,Event:event,Command:event.Command,Argument:event.Argument,Args:append([]string(nil),event.Args...),UserID:event.UserID,ServerID:event.ServerID,router:r}
	if err:=registration.handler(cc);err!=nil {r.mu.Lock();delete(r.seen,event.ID);for i,id:=range r.seenOrder{if id==event.ID{r.seenOrder=append(r.seenOrder[:i],r.seenOrder[i+1:]...);break}};r.mu.Unlock();result:=CommandResult{Status:StatusFailed,EventID:event.ID,Command:event.Command,Error:err};r.emit(result);return result}
	result:=CommandResult{Status:StatusHandled,EventID:event.ID,Command:event.Command};r.emit(result);return result
}

func (r *CommandRouter) HandleWebhook(ctx context.Context,input WebhookVerificationInput) CommandResult {if !r.client.VerifyWebhook(input){return CommandResult{Status:StatusRejected,Reason:"invalid_signature"}};var data any;if err:=json.Unmarshal(input.RawBody,&data);err!=nil{return CommandResult{Status:StatusRejected,Reason:"invalid_json"}};return r.Handle(ctx,data)}
func (r *CommandRouter) rememberLocked(id string){r.seen[id]=true;r.seenOrder=append(r.seenOrder,id);if len(r.seenOrder)>r.maxSeen{old:=r.seenOrder[0];r.seenOrder=r.seenOrder[1:];delete(r.seen,old)}}
func (r *CommandRouter) emit(result CommandResult){select{case r.Events<-result:default:}}

func (r *CommandRouter) Start(ctx context.Context,pollInterval time.Duration) error {if pollInterval==0{pollInterval=DefaultPollInterval};if pollInterval<100*time.Millisecond{return fmt.Errorf("poll interval must be at least 100ms")};r.mu.Lock();if r.running{r.mu.Unlock();return nil};if r.client.pollSubscriptionID==""&&r.client.webhookID==""{r.mu.Unlock();return fmt.Errorf("Poll transport is not configured")};runCtx,cancel:=context.WithCancel(ctx);r.cancel=cancel;r.done=make(chan struct{});r.running=true;done:=r.done;r.mu.Unlock();go r.pollLoop(runCtx,pollInterval,done);return nil}
func (r *CommandRouter) Running() bool {r.mu.Lock();defer r.mu.Unlock();return r.running}
func (r *CommandRouter) Stop(ctx context.Context) error {r.mu.Lock();if !r.running{r.mu.Unlock();return nil};cancel,done:=r.cancel,r.done;r.mu.Unlock();cancel();select{case <-done:return nil;case <-ctx.Done():return fmt.Errorf("timed out stopping command router: %w",ctx.Err())}}
func (r *CommandRouter) pollLoop(ctx context.Context,interval time.Duration,done chan struct{}) {defer close(done);defer func(){r.mu.Lock();r.running=false;r.cancel=nil;r.mu.Unlock()}();cursor:="";ticker:=time.NewTimer(0);defer ticker.Stop();for{select{case<-ctx.Done():return;case<-ticker.C:}
		response,err:=r.client.ListEvents(ctx,EventListOptions{Cursor:cursor});if err!=nil{r.emitError(err);ticker.Reset(interval);continue};obj,ok:=response.(map[string]any);if !ok{r.emitError(fmt.Errorf("Poll response was not an object"));ticker.Reset(interval);continue};if _,failed:=obj["error"];failed{r.emitError(fmt.Errorf("Poll request failed: %v",obj["error"]));if delay,ok:=obj["retryAfter"].(float64);ok&&time.Duration(delay*float64(time.Second))>interval{ticker.Reset(time.Duration(delay*float64(time.Second)))}else{ticker.Reset(interval)};continue}
		events,_:=obj["events"].([]any);ack:=[]string{};for _,item:=range events{result:=r.Handle(ctx,item);if result.Status!=StatusFailed{if m,ok:=item.(map[string]any);ok{if id,ok:=m["id"].(string);ok&&id!=""{ack=append(ack,id)}}}}
		if len(ack)>0&&r.client.pollSubscriptionID!=""{ackResult,ackErr:=r.client.AcknowledgeEvents(ctx,ack);if ackErr!=nil{r.emitError(ackErr)}else if m,ok:=ackResult.(map[string]any);ok{if e,failed:=m["error"];failed{r.emitError(fmt.Errorf("Poll acknowledgement failed: %v",e))}}}
		if hasMore,_:=obj["hasMore"].(bool);hasMore{if next,ok:=obj["nextCursor"].(string);ok{cursor=next}}else{cursor=""};ticker.Reset(interval)
	}}
func (r *CommandRouter) emitError(err error){select{case r.Errors<-err:default:}}

func (r *CommandRouter) reply(ctx context.Context,event CommandEvent,message string)(CommandSummary,error){if err:=validateMessage(message);err!=nil{return CommandSummary{},err};if event.UserID==""{return CommandSummary{},fmt.Errorf("player not found")};data,err:=r.client.GetPrivateServerAPI(ctx,[]ServerOption{Players});if err!=nil{return CommandSummary{},err};obj,ok:=data.(map[string]any);if !ok{return CommandSummary{},fmt.Errorf("player not found")};entries,ok:=obj["Players"].([]any);if !ok{return CommandSummary{},fmt.Errorf("player not found")};username:="";for _,entry:=range entries{m,ok:=entry.(map[string]any);if !ok{continue};name,id:=playerFields(m);if id==event.UserID&&safeUsername(name){username=name;break}};if username==""{return CommandSummary{},fmt.Errorf("player not found")};return r.client.SendPrivateServerCommand(ctx,[]string{":pm "+username+" "+sanitizeMessage(message)})}
func playerFields(m map[string]any)(string,string){if v,ok:=m["Player"].(string);ok{parts:=strings.Split(v,":");if len(parts)>1{return strings.Join(parts[:len(parts)-1],":"),parts[len(parts)-1]}};name:="";for _,k:=range []string{"Username","username","Name","name"}{if v,ok:=m[k].(string);ok{name=v;break}};for _,k:=range []string{"Id","ID","id","UserId","userId"}{if v,ok:=m[k];ok{return name,fmt.Sprint(v)}};return name,""}
var validUsername=regexp.MustCompile(`^[A-Za-z0-9_]+$`)
func safeUsername(v string)bool{return validUsername.MatchString(v)}
func validateMessage(v string)error{v=sanitizeMessage(v);if v==""{return fmt.Errorf("message must not be empty")};if len([]rune(v))>maxReplyLength{return fmt.Errorf("message must be %d characters or fewer",maxReplyLength)};return nil}
func sanitizeMessage(v string)string{return strings.TrimSpace(strings.Join(strings.Fields(strings.ReplaceAll(strings.ReplaceAll(v,"\r"," "),"\n"," "))," "))}

func normalizeCommandEvent(input any)(CommandEvent,bool){m,ok:=input.(map[string]any);if !ok{return CommandEvent{},false};data,_:=m["data"].(map[string]any);typ:=valueString(firstValue(m["event"],m["type"],data["event"],data["type"]));if !strings.EqualFold(typ,"customcommand"){return CommandEvent{},false};command:=normalizeCommandName(valueString(firstValue(m["command"],data["command"])));if command==""{return CommandEvent{},false};arg:=valueString(firstValue(m["argument"],data["argument"]));uid:=valueString(firstValue(m["userId"],data["userId"],data["userID"]));sid:=valueString(firstValue(m["serverId"],m["server"],data["serverId"],data["server"]));id:=valueString(firstValue(m["id"],m["_id"]));if id==""{encoded,_:=json.Marshal(m);hash:=sha256.Sum256(encoded);id=fmt.Sprintf("%x",hash)};username:=valueString(firstValue(m["username"],m["playerName"],data["username"],data["playerName"]));if username==""{username=valueString(firstValue(m["player"],m["Player"],data["player"],data["Player"]));if idx:=strings.LastIndex(username,":");idx>=0{username=username[:idx]}};event:=CommandEvent{ID:id,Type:"CustomCommand",Command:command,Argument:arg,Args:ParseArguments(arg),UserID:uid,ServerID:sid,Username:username,Timestamp:firstValue(m["timestamp"],data["timestamp"]),ReceivedAt:firstValue(m["createdAt"],m["receivedAt"],data["receivedAt"]),Raw:m};return event,true}
func firstValue(values ...any)any{for _,v:=range values{if v!=nil{return v}};return nil}
func valueString(v any)string{if v==nil{return ""};return fmt.Sprint(v)}

// ParseArguments splits whitespace-delimited arguments and supports single/double quoted values and backslash escapes.
func ParseArguments(input string)[]string{args:=[]string{};var current strings.Builder;quote:=rune(0);escaped:=false;for _,ch:=range input{if escaped{current.WriteRune(ch);escaped=false;continue};if ch=='\\'{escaped=true;continue};if quote!=0{if ch==quote{quote=0}else{current.WriteRune(ch)};continue};if ch=='\''||ch=='"'{quote=ch;continue};if ch==' '||ch=='\t'||ch=='\n'||ch=='\r'{if current.Len()>0{args=append(args,current.String());current.Reset()};continue};current.WriteRune(ch)};if escaped{current.WriteRune('\\')};if current.Len()>0{args=append(args,current.String())};return args}

