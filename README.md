# lightpod

A daemonless container engine written from scratch, for IoT, edge and robotics:
small, fast, security-first. Runs both rootfull and rootless.

It is built to stand alone — run, list and stop containers with no daemon and no
higher-level tool. It is also OCI-compatible, so other tools can drive it, but
that is a compatibility path rather than the reason it exists.

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

A created container inherits your stdio and holds it until it exits — the OCI
behaviour other tools depend on. Redirect to a file in scripts, or use `run` for
foreground work.

## Rootfull and rootless

Both are first class and chosen by the effective uid — run under `sudo` for
rootfull, there is no flag. The difference isn't cosmetic:

| | rootfull | rootless |
|---|---|---|
| device nodes | real, via mknod | host node bind mounted |
| cgroup | cgroup2 root | systemd-delegated subtree only |
| id mapping | not needed | `newuidmap` + `/etc/subuid` |
| NVIDIA GPU | full | limited |
| real-time (SCHED_FIFO) | yes, with `--cap-add CAP_SYS_NICE` | no |

Real-time scheduling is the one that surprises people: RT priority is a global
resource, so the kernel wants CAP_SYS_NICE in the initial user namespace. A
robotics control loop needs rootfull, the same way a GPU does.

Rootless cgroup limits need systemd delegation. Without it lightpod refuses to
start and tells you how to enable it, rather than quietly running unlimited.
`--cgroup=none` if you'd rather accept that.

## GPU and devices

lightpod does not touch the GPU itself. It wires in the NVIDIA Container
Toolkit and lets the toolkit do the work — the same thing Docker's chain does,
minus Docker:

```bash
lightpod run --rootfs ./cuda-app --gpu all gpu /app
lightpod run --rootfs ./cuda-app --gpu 0,1 gpu /app
```

`--gpu` hands the bundle to `nvidia-container-runtime`, the same shim Docker
uses, and lets it apply its edits — currently CDI, whatever the toolkit
defaults to. lightpod then runs the container itself, so nothing extra sits in
the process tree. If the shim is not installed it falls back to the toolkit's
prestart hook.

Needs the NVIDIA Container Toolkit on the host. `LIGHTPOD_GPU_MODE=runtime|hook`
pins one path; `LIGHTPOD_NVIDIA_RUNTIME` and `LIGHTPOD_NVIDIA_HOOK` point at
binaries in unusual places.

Everything else — cameras, serial ports, and accelerators that ship their
runtime in the image rather than needing driver injection — takes a host path:

```bash
lightpod run --rootfs ./app --device /dev/video0 --device /dev/ttyUSB0 cam /app
lightpod run --rootfs ./app --device /dev/hailo0 hailo /app          # Raspberry Pi AI Kit
lightpod run --rootfs ./app --device /dev/dri/renderD128 vpu /app
```

lightpod can also be run underneath `nvidia-container-runtime` itself, if you
already have that wiring. Same result, one more moving part.

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
- ✅ **M2.5** — volumes, host devices, NVIDIA GPUs via the toolkit's hook
- ⬜ **M2.6** — cgroup v1 and hybrid support (JetPack 5 and Ubuntu 20.04 need it)
- ⬜ **M3** — networking (veth/bridge/NAT, rootless user-mode, CNI)
- ⬜ **M4** — registry pull and overlayfs
- ⬜ **M5** — pods, systemd units, restart policies
- ⬜ **M6** — device cgroup rules, fuzzing, oci-runtime-tools compliance

## Requirements

Linux 4.18+, Go 1.25+. Resource limits currently need cgroup v2 (unified); v1
and hybrid systems are M2.6. Rootless also needs unprivileged user
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
