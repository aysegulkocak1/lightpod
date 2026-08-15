# lightpod

A daemonless, OCI-compatible container runtime written from scratch. Runs both
rootfull and rootless. Aimed at IoT, edge and robotics: small, fast, and
security-first.

> **Status: `v0.2.0-alpha`.** Isolation, the security layers and the OCI
> lifecycle work. **No networking and no image pull yet** — containers run from
> a rootfs directory you already have, and have no outside access.

## Why

runc + containerd is ~50MB of binary and 100ms+ of startup, most of it
generality a Jetson or a Pi doesn't need. If a robotics stack has to be up in
three seconds that's not a budget you can pay.

- **No external Go dependencies.** The `require` block in `go.mod` is empty. The
  seccomp BPF compiler, capability handling and cgroup layer are all plain
  syscalls, so the policy your containers actually run under is readable here.
- **No daemon.** Zero idle CPU; state lives on disk.
- **Secure by default.** Turning a layer off takes an explicit flag and prints a
  warning.

## Quick start

```bash
go build -o lightpod ./cmd/lightpod

# a one-binary rootfs to test against
mkdir -p rootfs
CGO_ENABLED=0 go build -o rootfs/check ./test/isolationcheck

./lightpod run --rootfs ./rootfs --cgroup none demo /check
```

What the container reports about itself:

```json
{"pid":1,"hostname":"lightpod","uid":0,"visibleProcs":1,
 "noNewPrivs":"1","seccomp":"2","capEff":"00000000800405fb",
 "kcoreReadable":false,"sysrqWritable":false,
 "mountAllowed":false,"hostRootVisible":false}
```

`seccomp:"2"` means the filter is loaded, `capEff` is the 11 default
capabilities, `mountAllowed:false` means the usual escape route is shut.

To see the policy before running anything:

```bash
./lightpod spec --rootfs ./rootfs /bin/sh
```

## Lifecycle

```bash
./lightpod spec --rootfs $PWD/rootfs /check sleep 30 > bundle/config.json
./lightpod create --bundle ./bundle web
./lightpod start web
./lightpod state web
./lightpod ps
./lightpod kill web TERM
./lightpod delete web
```

A created container inherits your stdio and holds it until it exits — that's the
runc contract podman and nvidia-container-runtime depend on. Redirect to a file
in scripts, or use `run` for foreground work.

## Rootfull and rootless

Both are first class, picked automatically, forced with `--rootless` /
`--rootfull`. The difference isn't cosmetic:

| | rootfull | rootless |
|---|---|---|
| device nodes | real, via mknod | host node bind mounted |
| cgroup | cgroup2 root | systemd-delegated subtree only |
| id mapping | not needed | `newuidmap` + `/etc/subuid` |
| NVIDIA GPU | full | limited |

Rootless cgroup limits need systemd delegation. Without it lightpod refuses to
start and tells you how to enable it, rather than quietly running unlimited.
`--cgroup=none` if you'd rather accept that.

## GPU

There's no NVIDIA-specific code in here. GPU support comes from sitting under
nvidia-container-runtime, which rewrites config.json and we apply it:

```bash
podman --runtime=$(command -v lightpod) run --device nvidia.com/gpu=0 <image> nvidia-smi
```

## Tests

```bash
go test ./...                          # unit, no root needed
go test -tags integration ./test/...   # starts real containers
```

Integration tests check isolation from inside the container, not from the
runtime's own logs.

## Roadmap

- ✅ **M1** — isolation and the security layers
- ✅ **M2** — OCI verbs, state store, hooks
- ⬜ **M2.5** — native CDI parsing, device cgroup rules
- ⬜ **M3** — networking (veth/bridge/NAT, rootless user-mode, CNI)
- ⬜ **M4** — registry pull and overlayfs
- ⬜ **M5** — pods, systemd units, restart policies
- ⬜ **M6** — fuzzing, oci-runtime-tools compliance

## Requirements

Linux 4.18+ with cgroup v2, Go 1.25+. Rootless also needs unprivileged user
namespaces, the `uidmap` package and an `/etc/subuid` entry. Targets amd64 and
arm64; 32-bit arm is best effort.

## Build

```bash
go build -ldflags "-s -w \
  -X github.com/aysegulkocak1/lightpod/pkg/version.Version=v0.2.0-alpha \
  -X github.com/aysegulkocak1/lightpod/pkg/version.Commit=$(git rev-parse --short HEAD) \
  -X github.com/aysegulkocak1/lightpod/pkg/version.BuildDate=$(date -u +%FT%TZ)" \
  -o lightpod ./cmd/lightpod

GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o lightpod-arm64 ./cmd/lightpod
```

## License

See [LICENSE](LICENSE).
