# lightpod Architecture

## 1. Proje Hedefi
- Podman benzeri **daemonless, rootless, multi-container engine**.
- Minimal, hafif ve güvenli runtime.
- Go ile yazılacak, modüler ve kolay genişletilebilir.

---

## 2. Katmanlar

### 2.1 pkg/runtime/
- **Amacı:** libcontainer alternatifi, container yaratma ve yönetimi.
- **Görevler:**
  - Process izolasyonu (`clone`, `unshare`)
  - Namespace yönetimi (`PID`, `NET`, `UTS`, `MOUNT`, `USER`)
  - Rootfs setup (`chroot`, `pivot_root`)
  - `/proc` mount
  - Cgroups v2 opsiyonel yönetimi
  - EntryPoint çalıştırma
- **Dosya Örnekleri:**
  - pkg/runtime/container.go
  - pkg/runtime/ns.go
  - pkg/runtime/fs.go
  - pkg/runtime/cgroup.go

### 2.2 pkg/monitor/
- **Amacı:** container processlerini izler (conmon alternatifi)
- **Görevler:**
  - stdout/stderr yönlendirme
  - Exit status takibi
  - Sinyalleri container PID1’e yönlendirme
- **Dosya Örnekleri:**
  - pkg/monitor/monitor.go

### 2.3 pkg/state/
- **Amacı:** container ve pod metadata yönetimi
- **Görevler:**
  - JSON tabanlı state dosyaları (`containers.json`, `pods.json`)
  - Persistent veya RAM-only mode
- **Dosya Örnekleri:**
  - pkg/state/state.go

### 2.4 pkg/security/
- **Amacı:** container güvenliği
- **Görevler:**
  - Seccomp filtreleri
  - Capability drop
  - AppArmor / SELinux opsiyonel
- **Dosya Örnekleri:**
  - pkg/security/seccomp.go
  - pkg/security/capabilities.go

### 2.5 pkg/pod/
- **Amacı:** birden fazla container’ı ortak ağ ve namespace ile çalıştırma
- **Dosya Örnekleri:**
  - pkg/pod/pod.go

### 2.6 cmd/lightpod/
- **Amacı:** CLI arayüzü
- **Örnek Komutlar:**
  - `lightpod create <name> --rootfs <path>`
  - `lightpod start <name>`
  - `lightpod exec <name> <command>`
  - `lightpod ps`
  - `lightpod stop <name>`
- **Dosya Örnekleri:**
  - cmd/lightpod/main.go
  - cmd/lightpod/commands.go

---

## 3. Versiyonlama
- `v0.0.1-alpha`: runtime-core (process izolasyonu + rootfs setup)


---

## 4. Notlar
- Proje Go 1.21+ ile yazılacak.
- Ubuntu 20.04 veya üstü, cgroups v2 aktif.
- Her modül opsiyonel ama çekirdek runtime (`pkg/runtime`) zorunlu.
- CLI, monitor ve state modülleri runtime üzerine inşa edilecek.
