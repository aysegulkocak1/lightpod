# lightpod Architecture

## 1. Proje Hedefi
- Podman benzeri **daemonless, rootless, multi-container engine**.
- Minimal, hafif ve güvenli runtime (Sıfır gereksiz bağımlılık, Pure Go).
- IoT Edge ve Yüksek Performanslı AI Uygulamalarına tam uyumlu düşük overhead yapısı.

---

## 2. Katmanlar

### 2.1 pkg/runtime/ (Core Engine)
- **Amacı:** libcontainer alternatifi, süreç izolasyon makinesi.
- **Görevler:**
  - Process izolasyonu (`clone`, `unshare`) ve Fork/Exec transition.
  - Namespace yönetimi (`PID`, `NET`, `UTS`, `MOUNT`, `USER`, `CGROUP`)
  - Standart I/O Stream ve TTY Yönetimi
  - Rootfs isolation (`pivot_root` ana referans) ve System Mounts (`/proc`, `/sys`, `/dev`)
  - Cgroups v2 ile RAM ve CPU limitlemeleri (Hardware Protection)
  - **Re-exec (PID 1) Stratejisi:** Go runtime'ını bellekten silmek ve konteyner namespace'lerini saflaştırmak için `/proc/self/exe init` Fork/Exec zinciri (Native Go `exec.Cmd` ile `Cloneflags` kullanılarak).
- **Dosya Örnekleri:** `container.go`, `ns.go`, `fs.go`, `cgroups.go`

### 2.2 pkg/network/ (CNI Katmanı) - [YENİ]
- **Amacı:** Konteynerlerin birbiriyle ve host'la dış dünyailetişimi.
- **Görevler:**
  - Veth-pair ve Bridge ağ arayüzlerinin oluşturulması.
  - IP atamaları, DNS geçişleri ve Iptables yönlendirmeleri.
  - Standart CNI (Container Network Interface) eklentileriyle uyumluluk.

### 2.3 pkg/image/ (Storage ve Registry) - [YENİ]
- **Amacı:** İmajları çekmek ve depolama (OverlayFS) katmanlarını çıkarmak.
- **Görevler:**
  - OCI Registry'den imaj indirme (pull) işlemleri.
  - OverlayFS kullanarak katmanlı (layered) rootfs bileleştirme işlemi. (Disk Tasarrufu)
  - Modellerin / verilerin bind mount (`-v host:container`) senaryoları.

### 2.4 pkg/device/ (CDI ve GPU) - [YENİ]
- **Amacı:** IoT ve AI odaklı donanım hızlandırıcıların içeri bağlanması.
- **Görevler:**
  - CDI (Container Device Interface) standardına uyumlu aygıt eşleme.
  - NVIDIA Container Toolkit "pre-start" hooks entegrasyonu (NVIDIA-SMI / Cuda uyumu).
  - Özel `/dev` mount kuralları (Edge Sensörler, Kameralar vs.)

### 2.5 pkg/monitor/ (Log & Metric)
- **Amacı:** daemonless çalışan süreçleri arkada izlemek.
- **Görevler:**
  - stdout/stderr loglarını host dizinlerine yönlendirmek ve yazdırmak.
  - Sinyal proxying ve exit state takibi.

### 2.6 pkg/security/
- **Amacı:** Container escape durumlarını engellemek.
- **Görevler:**
  - Capability (Drop/Add) izinleri: `capsbset_drop` ile host admin haklarının tırpanlanması.
  - Seccomp BPF Profil Oluşturma: `PR_SET_NO_NEW_PRIVS` şartının koşulması ve Native Go syscall ile BPF filtreleme.

### 2.7 pkg/state/ 
- **Amacı:** Durum ve meta-data tutulması.
- **Görevler:**
  - JSON tabanlı state (`/var/run/lightpod/containers.json`).

### 2.8 pkg/pod/
- **Amacı:** Multi-container paylaşımlı network ve ipc alanları yaratmak.

### 2.9 cmd/lightpod/
- **Amacı:** CLI arayüzü (komut satırı işlemleri).
- **Örnek Komutlar:**
  - `lightpod run`, `lightpod pull`, `lightpod ps`

---

## 3. Versiyonlama Planı
- `v0.1.0-alpha`: Runtime-Core (Isolates everything without network or image pull)
- `v0.2.0-alpha`: Pod ve Network Eklentileri (CNI)
- `v0.3.0-alpha`: Storage ve GPU Device (CDI) özellikleri (Tam AI Uyumlu)

---

## 4. Geliştirme Notları
- Sıfır ağır açık kaynak OCI paketi. Tüm manifest ayrıştırmaları (parsing) `encoding/json` standard library üzerinden Native yapılacaktır.
- Edge AI için ARM64 hedefli, `CGO_ENABLED=0` build alınabilecek şekilde struct odaklı tasarlanır.
