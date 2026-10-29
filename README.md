# LibertyGo

**LibertyGo** is a native Go SDK for ER:LC Private Server API v2 and Liberty Tools connections. It supports server queries, remote commands, ER:LC webhook signature verification, webhook relay status, Poll event listing/acknowledgement, and custom-command routing. Requires Go 1.21+. Install with `go get github.com/Liberty-Tools/LibertyGo`.

```go
package main

import (
    "context"
    "fmt"
    "os"

    libertygo "github.com/Liberty-Tools/LibertyGo"
)

func main() {
    client := libertygo.New(os.Getenv("ERLC_SERVER_KEY"))
    result, err := client.GetPrivateServerAPI(context.Background(), []libertygo.ServerOption{libertygo.Players, libertygo.Staff})
    if err != nil { panic(err) }
    fmt.Println(result)
}
```

## Liberty Tools Poll and command handlers

Keep the server key, Poll subscription ID, and Poll token in environment variables. A Poll token is secret and should not be committed or logged.

```go
client, err := libertygo.NewWithOptions(libertygo.Options{
    ServerKey: os.Getenv("ERLC_SERVER_KEY"),
    GlobalAPIKey: os.Getenv("ERLC_GLOBAL_API_KEY"),
    PollSubscriptionID: os.Getenv("POLL_SUBSCRIPTION_ID"),
    PollToken: os.Getenv("POLL_TOKEN"),
})
if err != nil { panic(err) }

router := client.Commands()
if err := router.Register("help", func(command *libertygo.CommandContext) error {
    _, err := command.Reply(command.Context, "Run ;commands for help")
    return err
}, libertygo.HandlerOptions{Cooldown: 10 * time.Second}); err != nil { panic(err) }

ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer cancel()
if err := router.Start(ctx, 2*time.Second); err != nil { panic(err) }
<-ctx.Done()
stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
defer stopCancel()
if err := router.Stop(stopCtx); err != nil { panic(err) }
```

Handlers receive normalized command names, the raw argument text, parsed arguments (single/double quotes and backslash escapes), user/server IDs, and the original event. `Reply` resolves the current player name by user ID before issuing a private message; `Announce` sends a server announcement. A handler error leaves the Poll event unacknowledged for retry. Listen on `router.Events` and `router.Errors` for outcomes and Poll failures.

For direct ER:LC webhooks, pass the exact timestamp, hex signature, and unmodified body bytes to `router.HandleWebhook`. The default built-in Ed25519 public key is used unless `WebhookPublicKey` is overridden with base64 DER/SPKI.

```go
result := router.HandleWebhook(context.Background(), libertygo.WebhookVerificationInput{
    Timestamp: request.Header.Get("x-signature-timestamp"),
    Signature: request.Header.Get("x-signature-ed25519"),
    RawBody: rawBody,
})
```

`ListEvents` accepts a cursor and a page limit from 1–100. `AcknowledgeEvents` is available only in v2 Poll mode. `WebhookStatus` checks the configured Liberty Tools relay.

Run `go build ./...`. API and relay payloads are unvalidated `any` values; validate fields before using them. The router and HTTP client cover the common LibertyJS flows, but do not currently share bucket-aware rate-limit state across client instances. See the root README for cross-language parity status.
