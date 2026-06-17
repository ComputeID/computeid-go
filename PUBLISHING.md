# Publishing & Distribution

This SDK lives at module path `github.com/ComputeID/computeid-go` (set in [`go.mod`](go.mod)). That path is the *canonical* source — it's how every consuming Go project finds the package. Where you actually push the git repo is a separate question.

---

## TL;DR — once you have org access

The repo is already `git init`'d, committed, and tagged `v0.1.0` locally. When `ComputeID` access lands:

```bash
# 1. On github.com/ComputeID, create empty repo "computeid-go"
#    (no README, no .gitignore, no license — those already live here)

cd /path/to/computeid-go
git remote add origin git@github.com:ComputeID/computeid-go.git

# 2. Push branch + tag. The release.yml workflow will run automatically when
#    it sees the tag, run the full test suite against a service-container
#    Postgres, then draft a GitHub Release with auto-generated notes.
git push -u origin main
git push origin v0.1.0
```

That's it. After ~3 minutes CI finishes and `go get github.com/ComputeID/computeid-go@v0.1.0` works for anyone.

---

## Pick the path that matches your access

### Path A — push directly to the org (recommended if you have write access)

See the TL;DR above. Two `git push` commands.

---

### Path B — stage on your personal account, promote to the org later

Useful when you want to iterate privately, get internal review, or you don't have repo-create rights in the org yet. **Keep the module path as-is** (`github.com/ComputeID/computeid-go`) — do *not* rename it to your username.

```bash
# On github.com/<your-user>, create a new empty repo "computeid-go" (private if you prefer)

cd /path/to/computeid-go
git init
git add .
git commit -m "Initial Go SDK"
git branch -M main
git remote add origin git@github.com:<your-user>/computeid-go.git
git push -u origin main
```

To **consume it** from another project of yours while it's still on your account, use a `replace` directive — that's how Go resolves a canonical path to a different actual location:

```bash
cd /path/to/other-project
go mod edit -replace github.com/ComputeID/computeid-go=github.com/<your-user>/computeid-go@main
go mod tidy
```

When you're ready to **promote to the org**:

```bash
# 1. Create the empty repo on github.com/ComputeID/computeid-go
# 2. Add it as a second remote and push
cd /path/to/computeid-go
git remote add org git@github.com:ComputeID/computeid-go.git
git push org main
git push org --tags
# 3. Consumers drop the `replace` directive and pin a tag
```

No code changes are required at promotion time because the module path was always the org path.

---

### Path C — GitHub repo transfer

Push to your personal account first, then use GitHub's **Settings → Transfer ownership** to move it to `ComputeID`. GitHub keeps git-level redirects so existing clones don't break.

Caveat: the Go module proxy caches by canonical path. If the module path in `go.mod` already says `ComputeID`, transfer "just works" once `proxy.golang.org` can reach the new location. If you ever renamed the module path to your personal namespace, you'd need to rename it back before publishing tags from the org repo.

In practice, **Path A or B is simpler than C** for a fresh repo.

---

## Consuming the SDK from another project

Once published (any of the paths above), import and use like any Go library:

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/ComputeID/computeid-go"
)

func main() {
    opts := []computeid.Option{computeid.WithAPIKey(os.Getenv("COMPUTEID_API_KEY"))}
    if base := os.Getenv("COMPUTEID_API_BASE"); base != "" {
        opts = append(opts, computeid.WithBaseURL(base))
    }
    c := computeid.NewClient(opts...)

    sp, err := c.RegisterAgent(context.Background(), computeid.AgentRegistration{
        Name:         "MyAgent",
        Organization: "Acme Corp",
        Capabilities: []string{"read", "web_browse", "api_call"},
    })
    if err != nil { log.Fatal(err) }
    log.Println("passport:", sp.PassportID)
}
```

**Two env knobs control where the SDK calls:**
- `COMPUTEID_API_BASE=http://localhost:8088` → your local `computeid-server`
- unset → production `https://api.aicomputeid.com`
- `COMPUTEID_API_KEY` → required only for the live API (optional on the local server)

---

## Local dev without publishing — `go.mod replace`

If you just want to consume the SDK from another local project on your machine — no GitHub involved — point Go at the local checkout:

```bash
cd /path/to/your-other-project
go mod init github.com/you/your-other-project   # if not already a module
go mod edit -replace github.com/ComputeID/computeid-go=/path/to/computeid-go
go get github.com/ComputeID/computeid-go@v0.0.0-00010101000000-000000000000
go mod tidy
```

Code-edit on the SDK and re-`go run ./...` in the consumer — changes show up immediately. Strip the `replace` line before publishing your consumer project.

---

## Running the local server alongside

Whichever distribution path you pick, the local server boots the same way:

```bash
# Against the existing leadpilot Postgres
cd /path/to/computeid-go
make db-up
make run     # listens on :8088

# Or as a self-contained Docker bundle
docker compose up --build   # server :8088, Postgres :5440
```

Then point your consuming project at it:
```bash
export COMPUTEID_API_BASE=http://localhost:8088
```

---

## Pre-publish checklist

Before `git push` on either Path A or B, double-check:

- [ ] `go vet ./...` clean
- [ ] `make test` green (43 tests)
- [ ] `make test-unit` green (works without Postgres)
- [ ] `LICENSE` present (MIT)
- [ ] `go.mod` module path is `github.com/ComputeID/computeid-go`
- [ ] No secrets in repo (no `.env`, no keys — `.gitignore` covers `*.test`, `*.out`)
- [ ] Tag follows semver (`v0.1.0`, `v0.2.0`, etc.) — required for `go get @vX.Y.Z`

---

## Recommendation

Given you already touch the org daily and the module path is locked to it, **Path A (push direct to org, tag `v0.1.0`)** is what I'd do. Path B is the right hedge if you want a review cycle before it's public.
