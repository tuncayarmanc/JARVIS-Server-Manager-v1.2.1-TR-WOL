import { Command } from "@tauri-apps/plugin-shell";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import "./style.css";

type ConnectionDurum = "offline" | "connecting" | "online" | "error";
type SshPhase = "starting" | "authenticated" | "failed" | "closed";
type SshErrorCode = "missing_client" | "invalid_settings" | "authentication_failed" | "host_key_mismatch" | "timeout" | "launch_failed" | "io_failed";
type SshStartReceipt = { readonly generation: number; readonly phase: "starting" | "closed" };
type SshLifecycleEvent = { readonly generation: number; readonly phase: SshPhase; readonly error: { readonly code: SshErrorCode; readonly messageTr: string; readonly retryable: boolean } | null };
type SshOutputEvent = { readonly generation: number; readonly data: string };

type UpdatePackage = {
  name: string;
  current: string;
  candidate: string;
  architecture: string;
};

type UpdateInfo = {
  available: number;
  security: number;
  rebootRequired: boolean;
  rebootPackages: string[];
  lastAptListYenile: string;
  packages: UpdatePackage[];
  history: string;
};

type MonitorSnapshot = {
  cpuPercent: number;
  memoryPercent: number;
  memoryUsedBytes: number;
  memoryTotalBytes: number;
  swapPercent: number;
  swapUsedBytes: number;
  swapTotalBytes: number;
  diskPercent: number;
  diskUsedBytes: number;
  diskTotalBytes: number;
  diskFreeBytes: number;
  load1: number;
  load5: number;
  load15: number;
  uptimeSeconds: number;
  uptime: string;
  temperature: number | null;
  networkArayüz: string;
  rxBytes: number;
  txBytes: number;
  processCount: number;
  topİşlem: { pid: number; command: string; cpuPercent: number; memoryPercent: number } | null;
};

type RemotePort = { proto: string; address: string; port: number; process: string };
type RemoteArayüz = { name: string; state: string; ipv4: string; ipv6: string };
type RemoteAccessSnapshot = { sshPort: number; authMethod: string; ufwActive: boolean | null; ufwOutput: string; ufwRuleCount: number; fail2banActive: boolean | null; fail2banOutput: string; fail2banJailCount: number; fail2banBanned: number; ports: RemotePort[]; interfaces: RemoteArayüz[]; authLog: string; };
type SecurityFinding = { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"; title: string; detail: string; recommendation: string; };
type SecurityCheck = { key: string; label: string; state: "PASS" | "WARN" | "FAIL" | "INFO" | "UNKNOWN"; value: string; detail: string; };
type SecurityListener = { protocol: string; address: string; port: number; process: string; pid: number | null; scope: string; service: string; status: string; firewall: string; exposure: string; unit: string | null; };
type SecurityAudit = { score: number; grade: string; sshPort: number; passwordAuthentication: boolean | null; pubkeyAuthentication: boolean | null; permitRootLogin: string; maxAuthTries: number | null; x11Forwarding: boolean | null; ufwActive: boolean | null; fail2banActive: boolean | null; externalListeningPorts: number; exposedListenerPorts: number; protectedListenerPorts: number; reviewListenerPorts: number; listeners: SecurityListener[]; findings: SecurityFinding[]; checks: SecurityCheck[]; generatedAt: string; };

type AppDurum = {
  host: string;
  port: string;
  username: string;
  keyPath: string;
  connection: ConnectionDurum;
  cpu: string;
  memory: string;
  disk: string;
  uptime: string;
  kernel: string;
  ubuntu: string;
  updateCount: string;
  temperature: string;
  rebootRequired: boolean;
  monitor: MonitorSnapshot | null;
  remote: RemoteAccessSnapshot | null;
  wolMac: string;
  wolBroadcast: string;
  wolPort: string;
};

const state: AppDurum = {
  host: localStorage.getItem("jarvis.host") || "192.168.1.10",
  port: localStorage.getItem("jarvis.port") || "22",
  username: localStorage.getItem("jarvis.username") || "armanc",
  keyPath: localStorage.getItem("jarvis.keyPath") || "C:\\Users\\arman\\.ssh\\id_ed25519",
  connection: "offline",
  cpu: "—",
  memory: "—",
  disk: "—",
  uptime: "—",
  kernel: "—",
  ubuntu: "—",
  updateCount: "—",
  temperature: "—",
  rebootRequired: false,
  monitor: null,
  remote: null,
  wolMac: localStorage.getItem("jarvis.wolMac") || "9C:A2:F4:E1:FD:46",
  wolBroadcast: localStorage.getItem("jarvis.wolBroadcast") || "192.168.1.255",
  wolPort: localStorage.getItem("jarvis.wolPort") || "9",
};

let terminal: Terminal | null = null;
let unlistenOutput: UnlistenFn | null = null;
let unlistenClosed: UnlistenFn | null = null;
let sshBaşlating = false;
let activeSshGeneration: number | null = null;
let sshListenersReady: Promise<void> | null = null;
const bufferedSshEvents = new Map<number, SshLifecycleEvent[]>();
const bufferedSshOutput = new Map<number, string[]>();
let updateInfo: UpdateInfo | null = null;
let updateBusy = false;

declare const __APP_VERSION__: string;

const app = document.querySelector<HTMLDivElement>("#app")!;

app.innerHTML = `
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">J</div>
        <div>
          <div class="brand-title">J.A.R.V.I.S</div>
          <div class="brand-subtitle">SUNUCU YÖNETİCİSİ</div>
        </div>
      </div>

      <div class="server-card">
        <div class="server-row">
          <span class="status-dot" id="sidebar-status-dot"></span>
          <span id="sidebar-status-text">OFFLINE</span>
        </div>
        <div class="server-name">Ubuntu Server</div>
        <div class="server-address" id="sidebar-address"></div>
      </div>

      <nav class="nav">
        <button class="nav-item active" data-page="dashboard"><span>⌂</span> Gösterge Paneli</button>
        <button class="nav-item" data-page="terminal"><span>›_</span> Terminal</button>
        <button class="nav-item" data-page="files"><span>▣</span> Dosyalar</button>
        <button class="nav-item" data-page="services"><span>◈</span> Servisler</button>
        <button class="nav-item" data-page="updates"><span>↻</span> Güncellemeler</button>
        <button class="nav-item" data-page="monitoring"><span>◌</span> İzleme</button>
        <button class="nav-item" data-page="logs"><span>≡</span> Günlükler</button>
        <button class="nav-item" data-page="remote"><span>⇄</span> Uzak Erişim</button>
        <button class="nav-item" data-page="security"><span>◉</span> Güvenlik</button>
      </nav>

      <div class="sidebar-footer">
        <button class="settings-button" id="settings-button">⚙ Ayarlar</button>
        <div class="version" id="app-version"></div>
      </div>
    </aside>

    <main class="main">
      <header class="topbar">
        <div>
          <div class="eyebrow">KONTROL MERKEZİ</div>
          <h1 id="page-title">Sunucu Paneli</h1>
        </div>
        <div class="top-actions">
          <button class="secondary-button" id="refresh-button">↻ Yenile</button>
          <button class="primary-button" id="connect-button">Bağlan</button>
        </div>
      </header>

      <div class="content">
        <section id="page-dashboard" class="page active-page">
          <div class="hero-grid">
            <div class="hero-card">
              <div class="card-heading">SUNUCU DURUMU</div>
              <div class="hero-status-row">
                <span class="large-status-dot" id="hero-dot"></span>
                <div>
                  <div class="hero-status" id="hero-status">OFFLINE</div>
                  <div class="muted" id="hero-status-subtitle">SSH bağlantısı</div>
                </div>
              </div>
              <div class="hero-meta">
                <div><span>Adres</span><strong id="hero-host"></strong></div>
                <div><span>Port</span><strong id="hero-port"></strong></div>
                <div><span>Kullanıcı</span><strong id="hero-user"></strong></div>
              </div>
            </div>

            <div class="metric-card"><span>CPU</span><strong id="metric-cpu">—</strong><div class="progress"><i id="bar-cpu"></i></div></div>
            <div class="metric-card"><span>RAM</span><strong id="metric-memory">—</strong><div class="progress"><i id="bar-memory"></i></div></div>
            <div class="metric-card"><span>DISK</span><strong id="metric-disk">—</strong><div class="progress"><i id="bar-disk"></i></div></div>
          </div>

          <div class="dashboard-grid">
            <div class="panel wide">
              <div class="panel-header">
                <div><div class="card-heading">SİSTEM</div><h2>Ubuntu Server</h2></div>
                <button class="ghost-button" id="system-refresh">İstatistikleri Güncelle</button>
              </div>
              <div class="system-grid">
                <div><span>Ubuntu</span><strong id="system-ubuntu">—</strong></div>
                <div><span>Kernel</span><strong id="system-kernel">—</strong></div>
                <div><span>Uptime</span><strong id="system-uptime">—</strong></div>
                <div><span>Güncellemeler</span><strong id="system-updates">—</strong></div>
                <div><span>Sıcaklık</span><strong id="system-temperature">—</strong></div>
                <div><span>Yeniden başlatma gerekli</span><strong id="system-reboot">—</strong></div>
              </div>
            </div>

            <div class="panel quick-actions">
              <div class="panel-header"><div><div class="card-heading">GÜÇ</div><h2>Sunucu Kontrolü</h2></div></div>
              <button class="danger-solid" id="power-toggle-button">⏻ Sunucuyu Aç</button>
              <button class="danger-outline" id="restart-button">↻ Sunucuyu Yeniden Başlat</button>
              <div class="warning-note">Sunucu kapalıysa Wake-on-LAN ile açılır; açıksa güvenli kapanış komutu gönderilir.</div>
            </div>

            <div class="panel wide update-panel">
              <div class="panel-header">
                <div><div class="card-heading">BAKIM</div><h2>Sistem Güncellemeleri</h2></div>
                <div class="update-badge" id="update-badge">—</div>
              </div>
              <p id="update-summary">Kullanılabilir paket güncellemelerini görmek için sunucuya bağlanın.</p>
              <div class="progress large"><i id="update-progress"></i></div>
              <div class="button-row">
                <button class="primary-button" id="update-button">Tümünü Güncelle</button>
                <button class="secondary-button" id="terminal-button">Terminali Aç</button>
              </div>
              <pre class="output-box" id="update-output">Henüz bir güncelleme işlemi başlatılmadı.</pre>
            </div>
          </div>
        </section>

        <section id="page-terminal" class="page">
          <div class="panel terminal-panel">
            <div class="panel-header terminal-head">
              <div><div class="card-heading">SSH</div><h2>Etkileşimli Terminal</h2></div>
              <div class="connection-pill" id="terminal-pill">BAĞLI DEĞİL</div>
            </div>
            <div class="terminal-wrap" id="terminal-wrap"></div>
            <div class="terminal-hint">Normal yazın · Ctrl+V / Shift+Insert yapıştır · Ctrl+Shift+C kopyala · Ctrl+C kes</div>
            <div class="terminal-actions">
              <button class="secondary-button" id="terminal-clear">Temizle</button>
              <button class="danger-outline" id="terminal-close">Bağlantıyı Kes</button>
            </div>
          </div>
        </section>


        <section id="page-files" class="page">
          <div class="panel file-manager-panel">
            <div class="panel-header">
              <div><div class="card-heading">SFTP / SCP</div><h2>Sunucu Dosyaları</h2></div>
              <div class="button-row">
                <button class="secondary-button" id="files-up-button">↑ Up</button>
                <button class="secondary-button" id="files-refresh-button">↻ Yenile</button>
              </div>
            </div>
            <div class="path-bar" id="files-path">/home/armanc</div>
            <div class="file-toolbar">
              <button class="primary-button" id="files-upload-button">↑ Yükle</button>
              <button class="secondary-button" id="files-new-folder-button">＋ New Folder</button>
              <button class="secondary-button" id="files-new-file-button">＋ New File</button>
            </div>
            <div class="file-table-wrap">
              <table class="file-table">
                <thead><tr><th>Ad</th><th>Tür</th><th>Boyut</th><th>Değiştirilme</th><th></th></tr></thead>
                <tbody id="files-table-body"><tr><td colspan="5" class="empty-state">Dosyalara göz atmak için sunucuya bağlanın.</td></tr></tbody>
              </table>
            </div>
            <div class="file-status" id="files-status">Hazır.</div>
          </div>
        </section>

        <div class="modal-backdrop" id="file-editor-modal">
          <div class="modal">
            <div class="modal-header"><div><div class="card-heading">UZAK DÜZENLEYİCİ</div><h2 id="file-editor-title">Dosya</h2></div><button class="icon-button" id="file-editor-close">×</button></div>
            <textarea id="file-editor-text" spellcheck="false"></textarea>
            <div class="modal-footer"><span class="muted" id="file-editor-status">Hazır</span><div class="button-row"><button class="secondary-button" id="file-editor-cancel">İptal</button><button class="primary-button" id="file-editor-save">Kaydet</button></div></div>
          </div>
        </div>

        <div class="context-menu" id="file-context-menu">
          <button data-action="open">Aç</button>
          <button data-action="download">İndir</button>
          <button data-action="rename">Yeniden Adlandır</button>
          <button data-action="delete">Sil</button>
          <button data-action="copy-path">Yolu Kopyala</button>
        </div>

        <section id="page-services" class="page">
          <div class="services-toolbar">
            <div>
              <div class="card-heading">SYSTEMD</div>
              <h2>Servisler</h2>
              <p class="muted">Sunucudaki seçili servisleri güvenli SSH komutları üzerinden yönet.</p>
            </div>
            <div class="button-row">
              <input class="service-search" id="service-search" type="search" placeholder="Servis ara..." autocomplete="off">
              <button class="secondary-button" id="services-refresh-button">↻ Yenile</button>
            </div>
          </div>
          <div class="service-filters" id="service-filters">
            <button class="filter-button active" data-filter="all">Tümü <span id="count-all">0</span></button>
            <button class="filter-button" data-filter="running">Çalışıyor <span id="count-running">0</span></button>
            <button class="filter-button" data-filter="stopped">Durduruldu <span id="count-stopped">0</span></button>
            <button class="filter-button" data-filter="failed">Hatalı <span id="count-failed">0</span></button>
            <button class="filter-button" data-filter="enabled">Etkin <span id="count-enabled">0</span></button>
          </div>
          <div class="services-grid" id="services-grid">
            <div class="panel empty-state-panel"><div class="placeholder-icon">◈</div><h2>Sunucuya bağlanın</h2><p class="muted">Servis durumu SSH bağlantısından sonra yüklenir.</p></div>
          </div>
          <div class="service-log-panel panel" id="service-log-panel" hidden>
            <div class="panel-header">
              <div><div class="card-heading">JOURNALCTL</div><h2 id="service-log-title">Servis Günlükleri</h2></div>
              <button class="secondary-button" id="service-log-close">Kapat</button>
            </div>
            <pre class="output-box tall" id="service-log-output">Henüz günlük yüklenmedi.</pre>
          </div>
        </section>

        <section id="page-updates" class="page">
          <div class="updates-grid">
            <div class="panel update-overview">
              <div class="panel-header">
                <div><div class="card-heading">APT / BAKIM</div><h2>Ubuntu Güncelleme Merkezi</h2></div>
                <div class="button-row"><button class="secondary-button" id="updates-refresh-button">↻ Kontrol Et</button><button class="primary-button" id="update-button-page">Tümünü Güncelle</button></div>
              </div>
              <div class="update-summary-grid">
                <div class="update-stat"><span>MEVCUT</span><strong id="updates-available">—</strong><small>paket güncellemesi</small></div>
                <div class="update-stat"><span>GÜVENLİK</span><strong id="updates-security">—</strong><small>en iyi çaba tespiti</small></div>
                <div class="update-stat"><span>YENİDEN BAŞLATMA</span><strong id="updates-reboot">—</strong><small>çekirdek/sistem yeniden başlatması</small></div>
                <div class="update-stat"><span>APT LİSTELERİ</span><strong id="updates-last-check">—</strong><small>paket listesi güncelliği</small></div>
              </div>
              <div class="update-command"><code>sudo -n apt update && sudo -n apt upgrade -y && sudo -n apt autoremove -y && sudo -n apt autoclean</code></div>
              <div class="update-status-line"><span id="updates-status-pill" class="update-status-pill">KONTROL EDİLMEDİ</span><span id="updates-status-text" class="muted">Sunucunun güncelleme durumunu kontrol et.</span></div>
              <pre class="output-box tall" id="update-output-page">Güncelleme Merkezi hazır.</pre>
            </div>

            <div class="panel">
              <div class="panel-header"><div><div class="card-heading">UPGRADABLE</div><h2>Kullanılabilir Paketler</h2></div><span class="muted" id="updates-package-count">0</span></div>
              <div class="package-list" id="updates-package-list"><div class="empty-state">Paketleri yüklemek için güncellemeleri kontrol edin.</div></div>
            </div>

            <div class="panel">
              <div class="panel-header"><div><div class="card-heading">YENİDEN BAŞLATMA</div><h2>Yeniden Başlatma Gereksinimi</h2></div></div>
              <div class="reboot-card" id="updates-reboot-card">
                <strong id="updates-reboot-title">Yeniden başlatma bilgisi yok.</strong>
                <p id="updates-reboot-detail" class="muted">Sunucuya bağlanın ve kontrol çalıştırın.</p>
              </div>
            </div>

            <div class="panel wide-update-panel">
              <div class="panel-header"><div><div class="card-heading">GEÇMİŞ</div><h2>Son Paket Değişiklikleri</h2></div><button class="secondary-button" id="updates-history-refresh">↻ Yenile</button></div>
              <pre class="output-box tall" id="updates-history-output">Geçmiş henüz yüklenmedi.</pre>
            </div>
          </div>
        </section>

        <section id="page-logs" class="page">
          <div class="logs-header">
            <div>
              <div class="card-heading">JOURNAL / SİSTEM GÜNLÜKLERİ</div>
              <h2>Günlük Merkezi</h2>
              <p class="muted">Servis ve sistem günlüklerini merkezi olarak ara, filtrele ve canlı izle.</p>
            </div>
            <div class="button-row logs-header-actions">
              <button class="secondary-button" id="logs-refresh-button">↻ Yenile</button>
              <button class="primary-button" id="logs-live-button">● Canlı</button>
            </div>
          </div>

          <div class="logs-layout">
            <div class="panel logs-control-panel">
              <div class="card-heading">FİLTRELER</div>
              <div class="logs-filter-grid">
                <label>Servis<select id="logs-service">
                  <option value="all">Tüm servisler</option>
                  <option value="ssh">SSH</option>
                  <option value="docker">Docker</option>
                  <option value="nginx">Nginx</option>
                  <option value="mariadb">MariaDB</option>
                  <option value="php8.5-fpm">PHP 8.5 FPM</option>
                  <option value="armanc-node-api">Armanc Node API</option>
                  <option value="armanc-python-api">Armanc Python API</option>
                  <option value="jarvis-host-telemetry">J.A.R.V.I.S Sunucu Telemetry</option>
                </select></label>
                <label>Seviye<select id="logs-level">
                  <option value="all">Tüm seviyeler</option>
                  <option value="error">HATA</option>
                  <option value="warn">UYARI</option>
                  <option value="info">BİLGİ</option>
                </select></label>
                <label>Zaman<select id="logs-since">
                  <option value="1">Son 1 saat</option>
                  <option value="6" selected>Son 6 saat</option>
                  <option value="24">Son 24 saat</option>
                  <option value="168">Son 7 gün</option>
                  <option value="all">Son kayıtlar</option>
                </select></label>
                <label>Satır<select id="logs-lines">
                  <option value="50">50</option>
                  <option value="100" selected>100</option>
                  <option value="200">200</option>
                  <option value="300">300</option>
                </select></label>
              </div>
              <label class="logs-search-label">Ara<input id="logs-search" type="search" placeholder="Günlüklerde ara..." autocomplete="off"></label>
              <div class="logs-summary-grid">
                <div><span>GÖSTERİLEN</span><strong id="logs-shown-count">0</strong></div>
                <div><span>HATA</span><strong id="logs-error-count">0</strong></div>
                <div><span>UYARI</span><strong id="logs-warn-count">0</strong></div>
                <div><span>BİLGİ</span><strong id="logs-info-count">0</strong></div>
              </div>
            </div>

            <div class="panel logs-output-panel">
              <div class="panel-header">
                <div>
                  <div class="card-heading">JOURNALCTL</div>
                  <h2 id="logs-output-title">Tüm servisler</h2>
                </div>
                <div class="logs-state"><span id="logs-status-pill">HAZIR</span><span class="muted" id="logs-last-refresh">—</span></div>
              </div>
              <div class="logs-output-wrap" id="logs-output-wrap"><pre id="logs-output">Sunucuya bağlanın ve günlükleri yükleyin.</pre></div>
            </div>
          </div>
        </section>

        <section id="page-monitoring" class="page">
          <div class="monitor-header">
            <div>
              <div class="card-heading">CANLI TELEMETRY</div>
              <h2>Sistem İzleme</h2>
              <p class="muted">CPU, RAM, disk, network ve süreçleri kalıcı SSH telemetry stream üzerinden canlı olarak izle.</p>
            </div>
            <div class="button-row">
              <label class="monitor-interval"><span>Yenile</span><select id="monitor-interval"><option value="2">2s</option><option value="5" selected>5s</option><option value="10">10s</option></select></label>
              <button class="secondary-button" id="monitor-refresh-button">↻ Yenile</button>
            </div>
          </div>

          <div class="monitor-stat-grid">
            <div class="monitor-stat-card"><div class="stat-top"><span>CPU</span><strong id="monitor-cpu">—</strong></div><div class="progress"><i id="monitor-cpu-bar"></i></div><small id="monitor-cpu-detail">CPU usage</small></div>
            <div class="monitor-stat-card"><div class="stat-top"><span>RAM</span><strong id="monitor-memory">—</strong></div><div class="progress"><i id="monitor-memory-bar"></i></div><small id="monitor-memory-detail">Bellek</small></div>
            <div class="monitor-stat-card"><div class="stat-top"><span>DISK /</span><strong id="monitor-disk">—</strong></div><div class="progress"><i id="monitor-disk-bar"></i></div><small id="monitor-disk-detail">Root filesystem</small></div>
            <div class="monitor-stat-card"><div class="stat-top"><span>SWAP</span><strong id="monitor-swap">—</strong></div><div class="progress"><i id="monitor-swap-bar"></i></div><small id="monitor-swap-detail">Swap kullanımı</small></div>
          </div>

          <div class="monitor-grid">
            <div class="panel monitor-chart-panel">
              <div class="panel-header"><div><div class="card-heading">PERFORMANCE</div><h2>CPU & Bellek</h2></div><span class="telemetry-live" id="monitor-live-pill">AKIŞ KAPALI</span></div>
              <canvas class="telemetry-chart" id="monitor-cpu-chart" height="180"></canvas>
              <div class="chart-legend"><span><i class="legend-dot cpu"></i> CPU</span><span><i class="legend-dot memory"></i> RAM</span></div>
            </div>
            <div class="panel monitor-chart-panel">
              <div class="panel-header"><div><div class="card-heading">NETWORK</div><h2 id="monitor-network-title">Trafik</h2></div><span class="muted" id="monitor-network-interface">—</span></div>
              <canvas class="telemetry-chart" id="monitor-network-chart" height="180"></canvas>
              <div class="chart-legend"><span><i class="legend-dot rx"></i> RX</span><span><i class="legend-dot tx"></i> TX</span></div>
            </div>
          </div>

          <div class="monitor-grid lower">
            <div class="panel">
              <div class="panel-header"><div><div class="card-heading">SİSTEM</div><h2>Çalışma Zamanı</h2></div></div>
              <div class="runtime-grid">
                <div><span>1 dk Yük</span><strong id="monitor-load1">—</strong></div>
                <div><span>5 dk Yük</span><strong id="monitor-load5">—</strong></div>
                <div><span>15 dk Yük</span><strong id="monitor-load15">—</strong></div>
                <div><span>Uptime</span><strong id="monitor-uptime">—</strong></div>
                <div><span>Sıcaklık</span><strong id="monitor-temperature">—</strong></div>
                <div><span>İşlemler</span><strong id="monitor-processes">—</strong></div>
              </div>
            </div>
            <div class="panel">
              <div class="panel-header"><div><div class="card-heading">TOP PROCESS</div><h2>En yüksek CPU kullanan işlem</h2></div></div>
              <div class="top-process" id="monitor-top-process"><div class="muted">İşlem verisi yok.</div></div>
            </div>
          </div>
        </section>


        <section id="page-remote" class="page">
          <div class="remote-header">
            <div>
              <div class="card-heading">NETWORK / GÜVENLİK</div>
              <h2>Uzak Erişim</h2>
              <p class="muted">SSH, ağ arayüzleri, açık dinleme portları, UFW ve Fail2Ban durumunu tek ekranda görüntüle.</p>
            </div>
            <div class="button-row"><button class="secondary-button" id="remote-refresh-button">↻ Yenile</button></div>
          </div>

          <div class="remote-grid">
            <div class="panel">
              <div class="panel-header"><div><div class="card-heading">SSH</div><h2>Uzak Bağlantı</h2></div><span id="remote-ssh-status" class="remote-pill">—</span></div>
              <div class="remote-kv-grid">
                <div><span>Adres</span><strong id="remote-host">—</strong></div>
                <div><span>Port</span><strong id="remote-port">—</strong></div>
                <div><span>Kullanıcı</span><strong id="remote-user">—</strong></div>
                <div><span>Auth</span><strong id="remote-auth">—</strong></div>
              </div>
            </div>

            <div class="panel">
              <div class="panel-header"><div><div class="card-heading">FIREWALL</div><h2>UFW</h2></div><span id="remote-ufw-status" class="remote-pill">—</span></div>
              <div class="security-summary-grid">
                <div><span>RULES</span><strong id="remote-ufw-rules">—</strong></div>
                <div><span>DETAILS</span><strong id="remote-ufw-detail-state">—</strong></div>
              </div>
              <pre class="output-box remote-output" id="remote-ufw-output">Güvenlik duvarı verisi yok.</pre>
            </div>

            <div class="panel">
              <div class="panel-header"><div><div class="card-heading">SALDIRI ÖNLEME</div><h2>Fail2Ban</h2></div><span id="remote-f2b-status" class="remote-pill">—</span></div>
              <div class="security-summary-grid">
                <div><span>JAILS</span><strong id="remote-f2b-jails">—</strong></div>
                <div><span>BANNED</span><strong id="remote-f2b-banned">—</strong></div>
              </div>
              <div class="remote-f2b" id="remote-f2b-output">Fail2Ban verisi yok.</div>
            </div>

            <div class="panel wide">
              <div class="panel-header"><div><div class="card-heading">DİNLENEN PORTLAR</div><h2>Açık Dinleme Portları</h2></div><span class="muted" id="remote-port-count">0 port</span></div>
              <div class="remote-table-wrap">
                <table class="remote-table"><thead><tr><th>Protokol</th><th>Yerel Adres</th><th>Port</th><th>İşlem</th></tr></thead><tbody id="remote-ports-body"><tr><td colspan="4" class="empty-state">Portları incelemek için yenileyin.</td></tr></tbody></table>
              </div>
            </div>

            <div class="panel wide">
              <div class="panel-header"><div><div class="card-heading">NETWORK</div><h2>Arayüzler</h2></div></div>
              <div class="remote-table-wrap"><table class="remote-table"><thead><tr><th>Arayüz</th><th>Durum</th><th>IPv4</th><th>IPv6</th></tr></thead><tbody id="remote-interfaces-body"><tr><td colspan="4" class="empty-state">Arayüzleri yüklemek için yenileyin.</td></tr></tbody></table></div>
            </div>

            <div class="panel wide">
              <div class="panel-header"><div><div class="card-heading">GÜVENLİK EVENTS</div><h2>Son SSH Kimlik Doğrulama Olayları</h2></div><span class="muted">Son 20</span></div>
              <pre class="output-box tall" id="remote-auth-log">Son SSH kimlik doğrulama olaylarını yüklemek için yenileyin.</pre>
            </div>
          </div>
        </section>

        <section id="page-security" class="page">
          <div class="security-header">
            <div>
              <div class="card-heading">GÜVENLİK MERKEZİ</div>
              <h2>Sunucu Güvenliği</h2>
              <p class="muted">SSH, firewall, Fail2Ban ve dinleme yüzeyini salt-okuma güvenlik denetimiyle analiz et.</p>
            </div>
            <div class="button-row"><button class="secondary-button" id="security-refresh-button">↻ Run Audit</button></div>
          </div>

          <div class="security-grid">
            <div class="panel security-score-panel">
              <div class="card-heading">GÜVENLİK PUANI</div>
              <div class="security-score-row"><strong id="security-score">—</strong><span>/ 100</span><span id="security-grade" class="security-grade">—</span></div>
              <div class="progress large"><i id="security-score-bar"></i></div>
              <p id="security-score-detail" class="muted">Güncel puanı hesaplamak için denetim çalıştırın.</p>
              <div class="security-meta" id="security-meta">Henüz denetim yok.</div>
            </div>

            <div class="panel">
              <div class="panel-header"><div><div class="card-heading">SSH SERTLEŞTİRME</div><h2>SSH Yapılandırması</h2></div><span id="security-ssh-pill" class="remote-pill">—</span></div>
              <div class="security-check-grid" id="security-ssh-checks"></div>
            </div>

            <div class="panel">
              <div class="panel-header"><div><div class="card-heading">FIREWALL</div><h2>UFW</h2></div><span id="security-ufw-pill" class="remote-pill">—</span></div>
              <div class="security-check-grid" id="security-ufw-checks"></div>
            </div>

            <div class="panel">
              <div class="panel-header"><div><div class="card-heading">SALDIRI ÖNLEME</div><h2>Fail2Ban</h2></div><span id="security-f2b-pill" class="remote-pill">—</span></div>
              <div class="security-check-grid" id="security-f2b-checks"></div>
            </div>

            <div class="panel">
              <div class="panel-header"><div><div class="card-heading">AĞ MARUZİYETİ</div><h2>Dinleme Yüzeyi</h2></div><span id="security-port-pill" class="remote-pill">—</span></div>
              <div class="security-exposure" id="security-exposure">Harici dinleyicileri incelemek için denetim çalıştırın.</div>
              <div class="security-listener-table-wrap" id="security-listener-table"><div class="empty-state">Henüz dinleyici envanteri yok.</div></div>
            </div>

            <div class="panel wide">
              <div class="panel-header"><div><div class="card-heading">GÜVENLİK BULGULARI</div><h2>Bulgular ve Öneriler</h2></div><span class="muted" id="security-finding-count">0 bulgu</span></div>
              <div id="security-findings" class="security-findings"><div class="empty-state">Bulguları yüklemek için denetim çalıştırın.</div></div>
            </div>

            <div class="panel wide">
              <div class="panel-header"><div><div class="card-heading">DENETİM KONTROLLERİ</div><h2>Kontrol Matrisi</h2></div></div>
              <div id="security-checks" class="security-checks-table"><div class="empty-state">Henüz kontrol yok.</div></div>
            </div>
          </div>
        </section>

        <div id="security-fix-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="security-fix-modal-title">
  <div class="modal-card security-fix-modal-card">
    <div class="panel-header"><div><div class="card-heading" id="security-fix-modal-heading">GÜVENLİK DÜZELTMESİ</div><h2 id="security-fix-modal-title">Düzeltmeyi Hazırla</h2></div><button class="secondary-button" id="security-fix-close">Kapat</button></div>
    <div class="fix-risk" id="security-fix-risk">SADECE ÖNİZLEME</div>
    <div class="fix-grid">
      <div><span>MEVCUT</span><code id="security-fix-current"></code></div>
      <div><span>ÖNERİLEN</span><code id="security-fix-proposed"></code></div>
    </div>
    <div class="fix-detail"><span>ETKİ</span><p id="security-fix-impact"></p></div>
    <div class="fix-detail"><span>GERİ ALMA</span><p id="security-fix-rollback"></p></div>
    <div class="fix-warning" id="security-fix-warning">Uygulama sırasında /etc/ssh yedeklenir, yapılandırma doğrulanır ve ssh servisi reload edilir.</div>
    <div class="fix-result" id="security-fix-result"></div>
    <div class="fix-actions"><button class="secondary-button" id="security-fix-rollback-button" hidden>Geri Al</button><button class="primary-button" id="security-fix-apply-button" hidden>Düzeltmeyi Uygula</button></div>
  </div>
</div>

<section id="page-settings" class="page">
          <div class="panel settings-panel">
            <div class="card-heading">BAĞLANTI</div>
            <h2>Sunucu Ayarları</h2>
            <div class="form-grid">
              <label>Sunucu<input id="input-host" type="text" autocomplete="off"></label>
              <label>Port<input id="input-port" type="number" min="1" max="65535"></label>
              <label>Kullanıcı adı<input id="input-user" type="text" autocomplete="off"></label>
              <label>SSH özel anahtar yolu<input id="input-key" type="text" autocomplete="off"></label>
              <label>Wake-on-LAN MAC<input id="input-wol-mac" type="text" placeholder="9C:A2:F4:E1:FD:46" autocomplete="off"></label>
              <label>Wake-on-LAN yayın adresi<input id="input-wol-broadcast" type="text" placeholder="192.168.1.255" autocomplete="off"></label>
              <label>Wake-on-LAN portu<input id="input-wol-port" type="number" min="1" max="65535" value="9"></label>
            </div>
            <div class="settings-actions"><button class="primary-button" id="save-settings">Ayarları Kaydet</button></div>
            <div class="warning-note">Özel anahtarın yolu yalnızca bu bilgisayarda saklanır. Uygulama özel anahtarınızı sunucuya yüklemez.</div>
          </div>
        </section>

        <section id="page-placeholder" class="page placeholder-page">
          <div class="panel placeholder">
            <div class="placeholder-icon">◈</div>
            <div class="card-heading">MODÜL</div>
            <h2 id="placeholder-title">Yakında</h2>
            <p>Bu modül mevcut SSH bağlantısının üzerine eklenecek.</p>
          </div>
        </section>
      </div>
    </main>
  </div>
`;

const q = <T extends Element>(selector: string) => document.querySelector<T>(selector)!;
q<HTMLElement>("#app-version").textContent = `v${__APP_VERSION__}`;

function setAddressText(): void {
  q<HTMLElement>("#sidebar-address").textContent = `${state.username}@${state.host}:${state.port}`;
  q<HTMLElement>("#hero-host").textContent = state.host;
  q<HTMLElement>("#hero-port").textContent = state.port;
  q<HTMLElement>("#hero-user").textContent = state.username;
}

function setConnectionStatus(connection: ConnectionDurum): void {
  state.connection = connection;
  const statusLabels: Record<ConnectionDurum, string> = { offline: "ÇEVRİMDIŞI", connecting: "BAĞLANIYOR", online: "BAĞLI", error: "HATA" };
  const text = statusLabels[connection];
  q<HTMLElement>("#sidebar-status-text").textContent = text;
  q<HTMLElement>("#hero-status").textContent = text;
  q<HTMLElement>("#terminal-pill").textContent = text;
  q<HTMLElement>("#connect-button").textContent = connection === "online" ? "Bağlantıyı Kes" : connection === "connecting" ? "Bağlanıyor…" : "Bağlan";
  q<HTMLElement>("#sidebar-status-dot").dataset.state = connection;
  q<HTMLElement>("#hero-dot").dataset.state = connection;
  q<HTMLElement>("#terminal-pill").dataset.state = connection;
  q<HTMLElement>("#hero-status-subtitle").textContent = connection === "online" ? "SSH bağlantısı kuruldu" : connection === "error" ? "SSH bağlantı hatası" : "SSH bağlantısı";
  setPowerButton(connection === "online" ? "online" : "offline");
  updateActionAvailability();
}

function setTextIfPresent(selector: string, value: string): void {
  const element = document.querySelector<HTMLElement>(selector);
  if (element) element.textContent = value;
}

function clearLiveConnectionData(): void {
  state.cpu = "—";
  state.memory = "—";
  state.disk = "—";
  state.uptime = "—";
  state.kernel = "—";
  state.ubuntu = "—";
  state.updateCount = "—";
  state.temperature = "—";
  state.rebootRequired = false;
  state.monitor = null;
  state.remote = null;
  updateInfo = null;
  updateMetric("#metric-cpu", "#bar-cpu", "—");
  updateMetric("#metric-memory", "#bar-memory", "—");
  updateMetric("#metric-disk", "#bar-disk", "—");
  setTextIfPresent("#metric-uptime", "—");
  setTextIfPresent("#metric-kernel", "—");
  setTextIfPresent("#metric-ubuntu", "—");
  setTextIfPresent("#metric-temperature", "—");
  setTextIfPresent("#system-updates", "—");
  setTextIfPresent("#system-temperature", "—");
  setTextIfPresent("#system-reboot", "—");
  setTextIfPresent("#update-badge", "—");
  setTextIfPresent("#update-summary", "Güncel veriler için sunucuya güvenli biçimde bağlanın.");
  renderUpdateInfo();
  clearSecurityAuditDisplay();
  clearRemoteAccessDisplay();
  resetMonitoringDisplay();
}

function updateActionAvailability(): void {
  const online = state.connection === "online";
  ["refresh-button", "system-refresh", "restart-button", "update-button", "update-button-page", "updates-refresh-button", "updates-history-refresh", "logs-refresh-button", "remote-refresh-button", "security-refresh-button"].forEach((id) => {
    const el = document.getElementById(id) as HTMLButtonElement | null;
    if (el) el.disabled = !online;
  });
}

function parsePercent(value: string): number {
  const n = Number.parseFloat(value.replace("%", ""));
  return Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : 0;
}

function updateMetric(id: string, bar: string, value: string): void {
  q<HTMLElement>(id).textContent = value;
  q<HTMLElement>(bar).style.width = `${parsePercent(value)}%`;
}

function appendOutput(target: string, text: string): void {
  const el = q<HTMLElement>(target);
  el.textContent = `${el.textContent}\n${text}`.trim();
  el.scrollTop = el.scrollHeight;
}

async function runRemoteCommand(commandText: string): Promise<string> {
  if (state.connection !== "online") {
    throw new Error("Sunucuya bağlı değilsin.");
  }

  const cmd = Command.create("ssh", [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=8",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=2",
    "-p", state.port,
    "-i", state.keyPath,
    `${state.username}@${state.host}`,
    commandText,
  ]);

  const output = await cmd.execute();
  if (output.code !== 0) {
    throw new Error(output.stderr.trim() || `SSH komutu başarısız (code ${output.code})`);
  }
  return output.stdout;
}

function handleSshLifecycle(event: SshLifecycleEvent): void {
  if (activeSshGeneration === null) {
    const queued = bufferedSshEvents.get(event.generation) ?? [];
    queued.push(event);
    bufferedSshEvents.set(event.generation, queued);
    return;
  }
  if (event.generation !== activeSshGeneration) return;
  switch (event.phase) {
    case "starting":
      return;
    case "authenticated":
      setConnectionStatus("online");
      terminal?.focus();
      void refreshDashboard();
      if (document.querySelector("#page-monitoring")?.classList.contains("active-page")) void startMonitoring();
      return;
    case "failed": {
      const message = event.error?.messageTr ?? "SSH bağlantısı doğrulanamadı.";
      terminal?.writeln(`\r\n\x1b[31mSSH bağlantısı başarısız: ${message}\x1b[0m`);
      activeSshGeneration = null;
      void stopGünlüklerLive();
      stopMonitoring();
      clearLiveConnectionData();
      setConnectionStatus("error");
      return;
    }
    case "closed":
      terminal?.writeln("\r\n\x1b[90mSSH oturumu kapandı.\x1b[0m");
      activeSshGeneration = null;
      void stopGünlüklerLive();
      stopMonitoring();
      clearLiveConnectionData();
      setConnectionStatus("offline");
      return;
  }
}

function handleSshOutput(event: SshOutputEvent): void {
  if (activeSshGeneration === null) {
    const queued = bufferedSshOutput.get(event.generation) ?? [];
    queued.push(event.data);
    bufferedSshOutput.set(event.generation, queued);
    return;
  }
  if (event.generation === activeSshGeneration) terminal?.write(event.data);
}

function flushBufferedSshEvents(generation: number): void {
  for (const event of bufferedSshEvents.get(generation) ?? []) handleSshLifecycle(event);
  bufferedSshEvents.delete(generation);
  for (const data of bufferedSshOutput.get(generation) ?? []) handleSshOutput({ generation, data });
  bufferedSshOutput.delete(generation);
}

async function ensureSshListeners(): Promise<void> {
  if (!sshListenersReady) {
    sshListenersReady = Promise.all([
      listen<SshLifecycleEvent>("ssh-lifecycle", (event) => handleSshLifecycle(event.payload)).then((unlisten) => { unlistenClosed = unlisten; }),
      listen<SshOutputEvent>("ssh-output", (event) => handleSshOutput(event.payload)).then((unlisten) => { unlistenOutput = unlisten; }),
    ]).then(() => undefined);
  }
  await sshListenersReady;
}

async function connectTerminal(): Promise<void> {
  if (sshBaşlating) return;

  if (state.connection === "online") {
    await disconnectTerminal();
    return;
  }

  sshBaşlating = true;
  setConnectionStatus("connecting");
  clearLiveConnectionData();
  ensureTerminal();
  await ensureSshListeners();
  terminal?.clear();
  terminal?.writeln(`\x1b[90mBağlanılıyor: ${state.username}@${state.host}:${state.port}...\x1b[0m`);

  try {
    const wrap = q<HTMLElement>("#terminal-wrap");
    const cols = terminal?.cols ?? Math.max(40, Math.floor((wrap.clientWidth - 24) / 8));
    const rows = terminal?.rows ?? Math.max(10, Math.floor((wrap.clientHeight - 24) / 18));

    const receipt = await invoke<SshStartReceipt>("start_ssh", {
      host: state.host,
      port: state.port,
      username: state.username,
      keyPath: state.keyPath,
      cols,
      rows,
    });

    if (receipt.phase !== "starting") throw new Error("SSH başlangıç makbuzu geçersiz.");
    activeSshGeneration = receipt.generation;
    flushBufferedSshEvents(receipt.generation);
  } catch (error) {
    clearLiveConnectionData();
    setConnectionStatus("error");
    terminal?.writeln(`\r\n\x1b[31mSSH başlatılamadı: ${String(error)}\x1b[0m`);
  } finally {
    sshBaşlating = false;
  }
}

async function disconnectTerminal(): Promise<void> {
  await stopGünlüklerLive();
  stopMonitoring();
  try {
    if (activeSshGeneration !== null) await invoke<SshStartReceipt>("close_ssh", { generation: activeSshGeneration });
  } catch (error) {
    terminal?.writeln(`\r\n\x1b[31mSSH kapatma hatası: ${String(error)}\x1b[0m`);
  } finally {
    activeSshGeneration = null;
    clearLiveConnectionData();
    setConnectionStatus("offline");
  }
}

function ensureTerminal(): void {
  if (terminal) return;

  terminal = new Terminal({
    cursorBlink: true,
    fontSize: 14,
    fontFamily: "Cascadia Mono, Consolas, monospace",
    convertEol: false,
    scrollback: 5000,
    rightClickSelectsWord: true,
    theme: {
      background: "#070a10",
      foreground: "#d7dde8",
      cursor: "#8da7ff",
      black: "#11151e",
      brightBlack: "#566072",
      green: "#55d187",
      brightGreen: "#75e6a0",
      blue: "#6e8bff",
      brightBlue: "#9cacff",
      yellow: "#e4c269",
      brightYellow: "#f1d98d",
      red: "#ff6b6b",
      brightRed: "#ff8b8b",
    },
  });

  terminal.open(q<HTMLElement>("#terminal-wrap"));

  const terminalWrap = q<HTMLElement>("#terminal-wrap");

  // xterm.js provides a dedicated custom-key hook. It is more reliable than
  // listening for keydown on the DOM because the same physical key event can
  // otherwise be handled by both the WebView and xterm.js. Returning false
  // from this hook tells xterm not to process the key a second time.
  terminal.attachCustomKeyEventHandler((event) => {
    if (event.type !== "keydown" || !terminal) return true;

    const key = event.key.toLowerCase();

    // Ctrl+V / Ctrl+Shift+V / Shift+Insert: paste exactly once.
    const pasteRequested = !event.altKey && (
      (event.ctrlKey && key === "v")
      || (event.ctrlKey && event.shiftKey && key === "v")
      || (event.shiftKey && !event.ctrlKey && key === "insert")
    );

    if (pasteRequested) {
      void navigator.clipboard.readText().then((text) => {
        const generation = activeSshGeneration;
        if (text && generation !== null) return invoke("write_ssh", { generation, data: text });
        return undefined;
      }).catch((error) => {
        terminal?.writeln(`\r\n\x1b[31mYapıştırma başarısız: ${String(error)}\x1b[0m\r\n`);
      });
      return false;
    }

    if (event.ctrlKey && !event.altKey && !event.metaKey && key === "c") {
      const selected = terminal.getSelection();

      if (selected.length > 0) {
        void navigator.clipboard.writeText(selected).then(() => {
          terminal?.clearSelection();
        }).catch((error) => {
          terminal?.writeln(`\r\n\x1b[31mKopyalama başarısız: ${String(error)}\x1b[0m\r\n`);
        });
      } else {
        // No selection: send a single ETX byte to the remote PTY.
        const generation = activeSshGeneration;
        if (generation !== null) void invoke("write_ssh", { generation, data: "\u0003" }).catch((error) => {
          terminal?.writeln(`\r\n\x1b[31mKesme başarısız: ${String(error)}\x1b[0m\r\n`);
        });
      }
      return false;
    }

    return true;
  });

  // Prevent the WebView's native paste event from injecting the clipboard a
  // second time. The actual paste is handled only by attachCustomKeyEventHandler.
  const preventNativePaste = (event: ClipboardEvent) => {
    event.preventDefault();
    event.stopPropagation();
  };
  terminalWrap.addEventListener("paste", preventNativePaste, true);

  terminal.onData((data) => {
    const generation = activeSshGeneration;
    if (state.connection !== "online" || generation === null) return;
    void invoke("write_ssh", { generation, data }).catch((error) => {
      terminal?.writeln(`\r\n\x1b[31mGirdi hatası: ${String(error)}\x1b[0m`);
    });
  });

  const resize = () => {
    if (!terminal) return;
    const wrap = q<HTMLElement>("#terminal-wrap");
    const cols = Math.max(40, Math.floor((wrap.clientWidth - 24) / 8));
    const rows = Math.max(10, Math.floor((wrap.clientHeight - 24) / 18));
    try {
      terminal.resize(cols, rows);
      const generation = activeSshGeneration;
      if (state.connection === "online" && generation !== null) {
        void invoke("resize_ssh", { generation, cols, rows }).catch(() => undefined);
      }
    } catch {
      // Ignore transient resize events while the view is hidden.
    }
  };

  new ResizeObserver(resize).observe(q<HTMLElement>("#terminal-wrap"));
  requestAnimationFrame(resize);

}

void listen<string>("logs-output", (event) => {
  if (!logsLive) return;
  const raw = event.payload.trimEnd();
  if (!raw) return;
  logsEntries.push({ raw, level: detectLogSeviye(raw) });
  if (logsEntries.length > 500) logsEntries.splice(0, logsEntries.length - 500);
  renderGünlükler();
  q<HTMLElement>("#logs-last-refresh").textContent = new Date().toLocaleTimeString();
  const output = q<HTMLElement>("#logs-output-wrap");
  output.scrollTop = output.scrollHeight;
}).then((unlisten) => { unlistenGünlüklerOutput = unlisten; }).catch(() => undefined);

void listen<string>("logs-error", (event) => {
  if (!logsLive) return;
  const raw = event.payload.trim();
  if (!raw) return;
  logsEntries.push({ raw, level: "error" });
  if (logsEntries.length > 500) logsEntries.splice(0, logsEntries.length - 500);
  renderGünlükler();
}).then((unlisten) => { unlistenGünlüklerHata = unlisten; }).catch(() => undefined);

void listen("logs-stream-closed", () => {
  if (!logsLive) return;
  logsLive = false;
  q<HTMLButtonElement>("#logs-live-button").dataset.live = "false";
  q<HTMLButtonElement>("#logs-live-button").textContent = "● Canlı";
  q<HTMLElement>("#logs-status-pill").textContent = "CLOSED";
  q<HTMLElement>("#logs-status-pill").dataset.state = "ready";
}).then((unlisten) => { unlistenGünlüklerClosed = unlisten; }).catch(() => undefined);


async function refreshDashboard(): Promise<void> {
  if (state.connection !== "online") return;
  const connectionAtRequest = state.connection;

  try {
    const data = await runRemoteCommand(`read -r _ u n sy i iw irq si st _ < /proc/stat; total1=$((u+n+sy+i+iw+irq+si+st)); idle1=$((i+iw)); sleep 0.4; read -r _ u n sy i iw irq si st _ < /proc/stat; total2=$((u+n+sy+i+iw+irq+si+st)); idle2=$((i+iw)); dt=$((total2-total1)); di=$((idle2-idle1)); cpu=$(awk -v t1="$total1" -v i1="$idle1" -v t2="$total2" -v i2="$idle2" 'BEGIN { dt=t2-t1; di=i2-i1; if (dt <= 0) print 0; else printf "%.0f", 100*(dt-di)/dt }'); mem=$(free -b | awk '/^Mem:/ {avail=$7; if (avail <= 0) avail=$2-$3; printf "%d %d %d", $2-avail, $2, avail}'); disk=$(df -B1 -P / | awk 'NR==2 {printf "%s %s %s %s", $3, $2, $4, $5}'); if [ -r /sys/class/thermal/thermal_zone0/temp ]; then temp=$(awk '{printf "%.1f", $1/1000}' /sys/class/thermal/thermal_zone0/temp); else temp=0; fi; ubuntu=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | sed 's/^"//; s/"$//'); printf "__JARVIS_CPU__%s\\n" "$cpu"; printf "__JARVIS_MEMORY__%s\\n" "$mem"; printf "__JARVIS_DISK__%s\\n" "$disk"; printf "__JARVIS_TEMP__%s\\n" "$temp"; printf "__JARVIS_UBUNTU__%s\\n" "$ubuntu"; printf "__JARVIS_KERNEL__%s\\n" "$(uname -r)"; printf "__JARVIS_UPTIME__%s\\n" "$(uptime -p)"; printf "__JARVIS_UPDATES__%s\\n" "$(apt list --upgradable 2>/dev/null | awk 'NR>1 && /\\// {c++} END {print c+0}')"; if [ -f /var/run/reboot-required ]; then printf "__JARVIS_REBOOT_REQUIRED__yes\\n"; else printf "__JARVIS_REBOOT_REQUIRED__no\\n"; fi`);

    const parsed: Record<string, string> = {};
    for (const rawLine of data.split(/\r?\n/)) {
      const line = rawLine.trim();
      const index = line.indexOf("__", 0);
      if (index < 0) continue;
      const separator = line.indexOf("__", 2);
      if (separator < 0) continue;
      const markerEnd = line.indexOf("__", 2);
      if (markerEnd < 0) continue;
      const match = line.match(/^(__JARVIS_[A-Z_]+__)(.*)$/);
      if (match) parsed[match[1]] = match[2].trim();
    }

    if (state.connection !== connectionAtRequest) return;
    const memoryParts = (parsed.__JARVIS_MEMORY__ || "").split(/\s+/);
    const diskParts = (parsed.__JARVIS_DISK__ || "").split(/\s+/);

    state.cpu = parsed.__JARVIS_CPU__ ? `${Math.max(0, Math.min(100, Number.parseInt(parsed.__JARVIS_CPU__, 10) || 0))}%` : "—";
    state.memory = memoryParts.length >= 2 && Number(memoryParts[1]) > 0 ? `${Math.round((Number(memoryParts[0]) / Number(memoryParts[1])) * 100)}%` : "—";
    state.disk = diskParts[3] || "—";
    state.temperature = parsed.__JARVIS_TEMP__ && parsed.__JARVIS_TEMP__ !== "0" ? `${parsed.__JARVIS_TEMP__} °C` : "—";
    state.ubuntu = parsed.__JARVIS_UBUNTU__ || "—";
    state.kernel = parsed.__JARVIS_KERNEL__ || "—";
    state.uptime = parsed.__JARVIS_UPTIME__ || "—";
    state.updateCount = parsed.__JARVIS_UPDATES__ || "0";
    state.rebootRequired = parsed.__JARVIS_REBOOT_REQUIRED__ === "yes";

    updateMetric("#metric-cpu", "#bar-cpu", state.cpu);
    updateMetric("#metric-memory", "#bar-memory", state.memory);
    updateMetric("#metric-disk", "#bar-disk", state.disk);
    q<HTMLElement>("#system-ubuntu").textContent = state.ubuntu;
    q<HTMLElement>("#system-kernel").textContent = state.kernel;
    q<HTMLElement>("#system-uptime").textContent = state.uptime;
    q<HTMLElement>("#system-updates").textContent = state.updateCount;
    q<HTMLElement>("#system-temperature").textContent = state.temperature;
    q<HTMLElement>("#system-reboot").textContent = state.rebootRequired ? "YES" : "NO";
    q<HTMLElement>("#update-badge").textContent = `${state.updateCount} available`;
    q<HTMLElement>("#update-summary").textContent = Number(state.updateCount) === 0
      ? "The server reports no pending APT paket güncellemesi."
      : `${state.updateCount} package update(s) are available.`;
  } catch (error) {
    appendOutput("#update-output", `[Dashboard] ${String(error)}`);
  }
}

function setUpdateBusy(busy: boolean): void {
  updateBusy = busy;
  ["#update-button", "#update-button-page", "#updates-refresh-button", "#updates-history-refresh"].forEach((id) => {
    const el = document.querySelector<HTMLButtonElement>(id);
    if (el) el.disabled = busy;
  });
}

function renderUpdateInfo(): void {
  const info = updateInfo;
  const available = info?.available ?? 0;
  q<HTMLElement>("#updates-available").textContent = info ? String(available) : "—";
  q<HTMLElement>("#updates-security").textContent = info ? String(info.security) : "—";
  q<HTMLElement>("#updates-reboot").textContent = info ? (info.rebootRequired ? "YES" : "NO") : "—";
  q<HTMLElement>("#updates-last-check").textContent = info?.lastAptListYenile || "—";
  q<HTMLElement>("#updates-package-count").textContent = info ? String(info.packages.length) : "0";
  q<HTMLElement>("#system-reboot").textContent = info ? (info.rebootRequired ? "Gerekli" : "Hayır") : state.rebootRequired ? "Gerekli" : "—";

  const pill = q<HTMLElement>("#updates-status-pill");
  const statusText = q<HTMLElement>("#updates-status-text");
  if (!info) {
    pill.textContent = "KONTROL EDİLMEDİ";
    pill.dataset.state = "unknown";
    statusText.textContent = "Sunucunun güncelleme durumunu kontrol et.";
  } else if (info.available === 0) {
    pill.textContent = "UP TO DATE";
    pill.dataset.state = "ok";
    statusText.textContent = info.rebootRequired ? "Paketler güncel, ancak yeniden başlatma gerekiyor." : "Bekleyen paket güncellemesi yok.";
  } else {
    pill.textContent = `${info.available} MEVCUT`;
    pill.dataset.state = "updates";
    statusText.textContent = info.rebootRequired ? "Güncellemeler var ve yeniden başlatma gerekiyor." : "Güncellenebilir paketler bulundu.";
  }

  const list = q<HTMLElement>("#updates-package-list");
  if (!info || info.packages.length === 0) {
    list.innerHTML = '<div class="empty-state">Bekleyen paket güncellemesi yok.</div>';
  } else {
    list.innerHTML = info.packages.map((pkg) => `
      <div class="package-row">
        <div><strong>${escapeHtml(pkg.name)}</strong><small>${escapeHtml(pkg.architecture)}</small></div>
        <div class="package-versions"><span>${escapeHtml(pkg.current)}</span><b>→</b><strong>${escapeHtml(pkg.candidate)}</strong></div>
      </div>`).join("");
  }

  q<HTMLElement>("#updates-reboot-title").textContent = info?.rebootRequired ? "Yeniden başlatma gerekli" : "Yeniden başlatma gerekmiyor";
  q<HTMLElement>("#updates-reboot-detail").textContent = info?.rebootRequired
    ? `Gerektiren paketler: ${info.rebootPackages.length ? info.rebootPackages.join(", ") : "sistem"}`
    : "Sunucu şu anda yeniden başlatma gereksinimi bildirmiyor.";
  q<HTMLElement>("#updates-history-output").textContent = info?.history || "Paket geçmişi bulunamadı.";
}

function clearRemoteAccessDisplay(): void {
  setTextIfPresent("#remote-host", "—");
  setTextIfPresent("#remote-port", "—");
  setTextIfPresent("#remote-user", "—");
  setTextIfPresent("#remote-auth", "—");
  setTextIfPresent("#remote-ufw-output", "Bağlantı verisi temizlendi.");
  setTextIfPresent("#remote-f2b-output", "Bağlantı verisi temizlendi.");
  setTextIfPresent("#remote-auth-log", "Bağlantı verisi temizlendi.");
  setTextIfPresent("#remote-port-count", "—");
  const ports = document.querySelector<HTMLElement>("#remote-ports-body");
  if (ports) ports.innerHTML = '<tr><td colspan="4" class="empty-state">Bağlantı verisi yok.</td></tr>';
  const interfaces = document.querySelector<HTMLElement>("#remote-interfaces-body");
  if (interfaces) interfaces.innerHTML = '<tr><td colspan="4" class="empty-state">Bağlantı verisi yok.</td></tr>';
  ["#remote-ssh-status", "#remote-ufw-status", "#remote-f2b-status"].forEach((selector) => {
    const pill = document.querySelector<HTMLElement>(selector);
    if (pill) {
      pill.textContent = "DOĞRULANAMADI";
      pill.dataset.state = "unknown";
    }
  });
}

async function inspectUpdates(): Promise<void> {
  if (state.connection !== "online") {
    window.alert("Önce sunucuya bağlanmalısın.");
    return;
  }
  setUpdateBusy(true);
  q<HTMLElement>("#update-output-page").textContent = "APT durumu kontrol ediliyor…";
  try {
    updateInfo = await invoke<UpdateInfo>("update_inspect", {
      host: state.host, port: state.port, username: state.username, keyPath: state.keyPath,
    });
    state.updateCount = String(updateInfo.available);
    state.rebootRequired = updateInfo.rebootRequired;
    renderUpdateInfo();
    q<HTMLElement>("#update-output-page").textContent = `Kontrol tamamlandı. ${updateInfo.available} paket güncellemesi mevcut.`;
    q<HTMLElement>("#update-summary").textContent = updateInfo.available === 0 ? "Sunucuda bekleyen APT paket güncellemesi yok." : `${updateInfo.available} paket güncellemesi mevcut.`;
    q<HTMLElement>("#update-badge").textContent = `${updateInfo.available} mevcut`;
  } catch (error) {
    q<HTMLElement>("#update-output-page").textContent = `Güncelleme kontrolü başarısız:\n${String(error)}`;
  } finally {
    setUpdateBusy(false);
  }
}

async function loadUpdateHistory(): Promise<void> {
  if (state.connection !== "online") return;
  try {
    const history = await invoke<string>("update_history", {
      host: state.host, port: state.port, username: state.username, keyPath: state.keyPath,
    });
    if (!updateInfo) updateInfo = { available: 0, security: 0, rebootRequired: false, rebootPackages: [], lastAptListYenile: "—", packages: [], history };
    else updateInfo.history = history;
    renderUpdateInfo();
  } catch (error) {
    q<HTMLElement>("#updates-history-output").textContent = `Paket geçmişi yüklenemedi:\n${String(error)}`;
  }
}

async function performUpdate(target = "#update-output"): Promise<void> {
  if (state.connection !== "online") {
    window.alert("Önce sunucuya bağlanmalısın.");
    return;
  }
  const output = q<HTMLElement>(target);
  output.textContent = "Bu sürüm güncellemeleri çalıştırmaz. Paket önizlemesi ve yeniden başlatma gereksinimi ayrı olarak doğrulanır.";
  await inspectUpdates();
}
function setPowerButton(mode: "offline" | "starting" | "online" | "stopping"): void {
  const button = q<HTMLButtonElement>("#power-toggle-button");
  const restart = q<HTMLButtonElement>("#restart-button");
  const labels = { offline: "⏻ Sunucuyu Aç", starting: "⏳ Sunucu Açılıyor…", online: "⏻ Sunucuyu Kapat", stopping: "⏳ Sunucu Kapanıyor…" };
  button.textContent = labels[mode];
  button.dataset.state = mode;
  button.disabled = mode === "starting" || mode === "stopping";
  restart.disabled = mode !== "online";
}

async function waitForServerDurum(expectedOnline: boolean, timeoutMs = 45000): Promise<boolean> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const online = await invoke<boolean>("probe_server", { host: state.host, port: state.port, timeoutMs: 1200 });
      if (online === expectedOnline) return true;
    } catch { /* tekrar dene */ }
    await new Promise(resolve => setTimeout(resolve, 2500));
  }
  return false;
}

async function toggleServerPower(): Promise<void> {
  if (state.connection === "connecting") return;
  if (state.connection === "online") {
    if (!window.confirm("Ubuntu sunucusunu güvenli şekilde kapatmak istiyor musun?")) return;
    setPowerButton("stopping");
    try {
      await remotePower("shutdown", false);
      await disconnectTerminal();
      const stopped = await waitForServerDurum(false, 30000);
      setConnectionStatus("offline");
      setPowerButton("offline");
      window.alert(stopped ? "Sunucu kapatıldı." : "Kapatma komutu gönderildi. Sunucunun kapanması biraz daha sürebilir.");
    } catch (error) {
      setPowerButton("online");
      window.alert(`Sunucu kapatılırken hata oluştu: ${String(error)}`);
    }
    return;
  }

  if (!window.confirm(`Wake-on-LAN ile ${state.host} sunucusunu açmak istiyor musun?`)) return;
  setPowerButton("starting");
  try {
    await invoke<string>("wake_on_lan", {
      mac: state.wolMac,
      broadcast: state.wolBroadcast,
      port: Number(state.wolPort) || 9,
      repeats: 3,
    });
    const started = await waitForServerDurum(true, 60000);
    if (!started) {
      setPowerButton("offline");
      window.alert("Wake-on-LAN paketi gönderildi ancak sunucuya henüz ulaşılamıyor. BIOS/WOL ve ağ ayarlarını kontrol edin.");
      return;
    }
    await connectTerminal();
    setPowerButton("online");
  } catch (error) {
    setPowerButton("offline");
    window.alert(`Sunucu açılamadı: ${String(error)}`);
  }
}

async function remotePower(action: "restart" | "shutdown", askForConfirmation = true): Promise<void> {
  if (state.connection !== "online") {
    window.alert("Önce sunucuya bağlanmalısın.");
    return;
  }

  const label = action === "restart" ? "yeniden başlatmak" : "kapatmak";
  if (askForConfirmation && !window.confirm(`Ubuntu sunucusunu şimdi ${label} istiyor musun?`)) return;

  await runRemoteCommand(action === "restart" ? "sudo -n /usr/local/sbin/jarvis-remediation --reboot" : "sudo -n /usr/local/sbin/jarvis-remediation --poweroff");
}



type RemoteFileEntry = {
  name: string;
  path: string;
  kind: "file" | "directory" | "symlink";
  size: number;
  modified: string;
};

let currentRemotePath = `/home/${state.username}`;
let fileEntries: RemoteFileEntry[] = [];
let selectedFile: RemoteFileEntry | null = null;

function formatFileSize(size: number): string {
  if (!Number.isFinite(size) || size <= 0) return size === 0 ? "0 B" : "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = size;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

function formatModified(epoch: string): string {
  const n = Number(epoch);
  if (!Number.isFinite(n) || n <= 0) return "—";
  return new Date(n * 1000).toLocaleString();
}

function setFilesStatus(text: string): void {
  q<HTMLElement>("#files-status").textContent = text;
}

function renderFileRows(): void {
  const body = q<HTMLTableSectionElement>("#files-table-body");
  if (fileEntries.length === 0) {
    body.innerHTML = `<tr><td colspan="5" class="empty-state">Klasör boş.</td></tr>`;
    return;
  }
  body.innerHTML = fileEntries.map((entry, index) => `
    <tr data-index="${index}" class="file-row">
      <td><span class="file-name-cell"><span class="file-icon">${entry.kind === "directory" ? "📁" : entry.kind === "symlink" ? "🔗" : "📄"}</span>${escapeHtml(entry.name)}</span></td>
      <td>${entry.kind}</td>
      <td>${entry.kind === "directory" ? "—" : formatFileSize(entry.size)}</td>
      <td>${formatModified(entry.modified)}</td>
      <td><button class="row-more" data-index="${index}">⋮</button></td>
    </tr>`).join("");

  body.querySelectorAll<HTMLTableRowElement>(".file-row").forEach((row) => {
    row.addEventListener("dblclick", () => {
      const entry = fileEntries[Number(row.dataset.index)];
      if (entry.kind === "directory") { currentRemotePath = entry.path; void loadFiles(); }
      else { void openRemoteFile(entry); }
    });
    row.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      const entry = fileEntries[Number(row.dataset.index)];
      showFileContextMenu(event.clientX, event.clientY, entry);
    });
  });
  body.querySelectorAll<HTMLButtonElement>(".row-more").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      const entry = fileEntries[Number(button.dataset.index)];
      const rect = button.getBoundingClientRect();
      showFileContextMenu(rect.left - 180, rect.bottom + 4, entry);
    });
  });
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

async function loadFiles(): Promise<void> {
  if (state.connection !== "online") { setFilesStatus("Sunucuya bağlanın first."); return; }
  setFilesStatus("Klasör yükleniyor…");
  try {
    fileEntries = await invoke<RemoteFileEntry[]>("file_list", {
      host: state.host,
      port: state.port,
      username: state.username,
      keyPath: state.keyPath,
      path: currentRemotePath,
    });
    q<HTMLElement>("#files-path").textContent = currentRemotePath;
    renderFileRows();
    setFilesStatus(`${fileEntries.length} öğe`);
  } catch (error) {
    setFilesStatus(`Listeleme başarısız: ${String(error)}`);
  }
}

async function openRemoteFile(entry: RemoteFileEntry): Promise<void> {
  if (state.connection !== "online") return;
  if (entry.kind !== "file") { window.alert("Bu öğe düzenlenebilir bir dosya değil."); return; }
  try {
    const content = await invoke<string>("file_read", {
      host: state.host, port: state.port, username: state.username, keyPath: state.keyPath, path: entry.path,
    });
    q<HTMLElement>("#file-editor-title").textContent = entry.path;
    q<HTMLTextAreaElement>("#file-editor-text").value = content;
    q<HTMLElement>("#file-editor-status").textContent = "Loaded";
    q<HTMLElement>("#file-editor-modal").classList.add("open");
    selectedFile = entry;
  } catch (error) {
    window.alert(`Dosya açılamadı:\n${String(error)}`);
  }
}

function hideFileContextMenu(): void { q<HTMLElement>("#file-context-menu").classList.remove("open"); }
function showFileContextMenu(x: number, y: number, entry: RemoteFileEntry): void {
  selectedFile = entry;
  const menu = q<HTMLElement>("#file-context-menu");
  menu.style.left = `${Math.max(8, Math.min(window.innerWidth - 210, x))}px`;
  menu.style.top = `${Math.max(8, Math.min(window.innerHeight - 220, y))}px`;
  menu.classList.add("open");
}

async function uploadFile(): Promise<void> {
  if (state.connection !== "online") return;
  const selected = await openFileDialog({ multiple: false, directory: false });
  const localPath = Array.isArray(selected) ? selected[0] : selected;
  if (!localPath) return;
  setFilesStatus("Yükleniyor…");
  try {
    await invoke("file_upload", { host: state.host, port: state.port, username: state.username, keyPath: state.keyPath, localPath: localPath, remoteDir: currentRemotePath });
    await loadFiles();
    setFilesStatus("Yükleme tamamlandı.");
  } catch (error) { setFilesStatus(`Yükleme başarısız: ${String(error)}`); }
}

async function downloadFile(entry: RemoteFileEntry): Promise<void> {
  const target = await saveFileDialog({ defaultPath: entry.name });
  if (!target) return;
  setFilesStatus("İndiriliyor…");
  try {
    await invoke("file_download", { host: state.host, port: state.port, username: state.username, keyPath: state.keyPath, remotePath: entry.path, localPath: target });
    setFilesStatus("İndirme tamamlandı.");
  } catch (error) { setFilesStatus(`İndirme başarısız: ${String(error)}`); }
}

async function createRemoteFolder(): Promise<void> {
  const name = window.prompt("Yeni klasör adı:");
  if (!name) return;
  try {
    await invoke("file_mkdir", { host: state.host, port: state.port, username: state.username, keyPath: state.keyPath, path: currentRemotePath, name: name.trim() });
    await loadFiles();
  } catch (error) { window.alert(String(error)); }
}

async function createRemoteFile(): Promise<void> {
  const name = window.prompt("Yeni dosya adı:");
  if (!name) return;
  try {
    await invoke("file_touch", { host: state.host, port: state.port, username: state.username, keyPath: state.keyPath, path: currentRemotePath, name: name.trim() });
    await loadFiles();
  } catch (error) { window.alert(String(error)); }
}

async function renameRemoteFile(entry: RemoteFileEntry): Promise<void> {
  const name = window.prompt("Yeni ad:", entry.name);
  if (!name || name.trim() === entry.name) return;
  try {
    await invoke("file_rename", { host: state.host, port: state.port, username: state.username, keyPath: state.keyPath, oldPath: entry.path, newName: name.trim() });
    await loadFiles();
  } catch (error) { window.alert(String(error)); }
}

async function deleteRemoteFile(entry: RemoteFileEntry): Promise<void> {
  if (!window.confirm(`"${entry.name}" silinsin mi?\nBu işlem geri alınamaz.`)) return;
  try {
    await invoke("file_delete", { host: state.host, port: state.port, username: state.username, keyPath: state.keyPath, path: entry.path, isDirectory: entry.kind === "directory" });
    await loadFiles();
  } catch (error) { window.alert(String(error)); }
}

async function openFileDialog(options: { multiple?: boolean; directory?: boolean }): Promise<string | string[] | null> {
  const { open } = await import("@tauri-apps/plugin-dialog");
  return await open({ title: "Upload file", multiple: options.multiple ?? false, directory: options.directory ?? false });
}

async function saveFileDialog(options: { defaultPath?: string }): Promise<string | null> {
  const { save } = await import("@tauri-apps/plugin-dialog");
  return await save({ title: "Save file", defaultPath: options.defaultPath });
}

async function saveRemoteFile(): Promise<void> {
  if (!selectedFile) return;
  const content = q<HTMLTextAreaElement>("#file-editor-text").value;
  q<HTMLElement>("#file-editor-status").textContent = "Saving…";
  try {
    await invoke("file_write", { host: state.host, port: state.port, username: state.username, keyPath: state.keyPath, path: selectedFile.path, content });
    q<HTMLElement>("#file-editor-status").textContent = "Kaydedildi ✓";
    await loadFiles();
  } catch (error) {
    q<HTMLElement>("#file-editor-status").textContent = `Kaydetme başarısız: ${String(error)}`;
  }
}


type ServisInfo = {
  name: string;
  unit: string;
  description: string;
  active: string;
  subDurum: string;
  enabled: string;
  mainPid: number;
  memory: string;
  cpu: string;
};

let services: ServisInfo[] = [];
let serviceFilter = "all";

function serviceMatchesFilter(service: ServisInfo): boolean {
  if (serviceFilter === "running") return service.active === "active";
  if (serviceFilter === "stopped") return service.active === "inactive" || service.active === "unknown";
  if (serviceFilter === "failed") return service.active === "failed";
  if (serviceFilter === "enabled") return service.enabled === "enabled";
  return true;
}

function serviceMatchesAra(service: ServisInfo, search: string): boolean {
  if (!search) return true;
  const haystack = `${service.name} ${service.unit} ${service.description}`.toLowerCase();
  return haystack.includes(search.toLowerCase());
}

function serviceStatusClass(service: ServisInfo): string {
  if (service.active === "active") return "running";
  if (service.active === "failed") return "failed";
  if (service.active === "activating") return "activating";
  return "stopped";
}

function serviceStatusLabel(service: ServisInfo): string {
  if (service.active === "active") return "RUNNING";
  if (service.active === "failed") return "FAILED";
  if (service.active === "activating") return "STARTING";
  if (service.active === "inactive") return "STOPPED";
  return service.active.toUpperCase();
}

function renderServisCounts(): void {
  const all = services.length;
  const running = services.filter((s) => s.active === "active").length;
  const stopped = services.filter((s) => s.active === "inactive" || s.active === "unknown").length;
  const failed = services.filter((s) => s.active === "failed").length;
  const enabled = services.filter((s) => s.enabled === "enabled").length;
  q<HTMLElement>("#count-all").textContent = String(all);
  q<HTMLElement>("#count-running").textContent = String(running);
  q<HTMLElement>("#count-stopped").textContent = String(stopped);
  q<HTMLElement>("#count-failed").textContent = String(failed);
  q<HTMLElement>("#count-enabled").textContent = String(enabled);
}

function renderServisler(): void {
  const grid = q<HTMLElement>("#services-grid");
  const search = q<HTMLInputElement>("#service-search").value.trim();
  const visible = services.filter((service) => serviceMatchesFilter(service) && serviceMatchesAra(service, search));
  if (visible.length === 0) {
    grid.innerHTML = `<div class="panel empty-state-panel"><div class="placeholder-icon">◈</div><h2>Servis bulunamadı</h2><p class="muted">Filtreyi veya arama terimini değiştir.</p></div>`;
    return;
  }
  grid.innerHTML = visible.map((service) => {
    const css = serviceStatusClass(service);
    const isRunning = service.active === "active";
    return `
      <article class="service-card">
        <div class="service-card-top">
          <div>
            <div class="service-name">${escapeHtml(service.name)}</div>
            <div class="service-unit">${escapeHtml(service.unit)}</div>
          </div>
          <div class="service-status ${css}"><span></span>${serviceStatusLabel(service)}</div>
        </div>
        <p class="service-description">${escapeHtml(service.description)}</p>
        <div class="service-meta-grid">
          <div><span>Etkin</span><strong>${escapeHtml(service.enabled.toUpperCase())}</strong></div>
          <div><span>PID</span><strong>${service.mainPid ? String(service.mainPid) : "—"}</strong></div>
          <div><span>Bellek</span><strong>${escapeHtml(service.memory)}</strong></div>
          <div><span>CPU</span><strong>${escapeHtml(service.cpu)}</strong></div>
        </div>
        <div class="service-actions">
          <button class="secondary-button" data-service-action="start" data-service="${escapeHtml(service.unit)}" ${isRunning ? "disabled" : ""}>Başlat</button>
          <button class="danger-outline" data-service-action="stop" data-service="${escapeHtml(service.unit)}" ${isRunning ? "" : "disabled"}>Durdur</button>
          <button class="secondary-button" data-service-action="restart" data-service="${escapeHtml(service.unit)}">Yeniden Başlat</button>
          <button class="ghost-button" data-service-logs="${escapeHtml(service.unit)}">Günlükler</button>
        </div>
      </article>`;
  }).join("");

  grid.querySelectorAll<HTMLButtonElement>("[data-service-action]").forEach((button) => {
    button.addEventListener("click", () => {
      const unit = button.dataset.service || "";
      const action = button.dataset.serviceAction || "";
      const service = services.find((item) => item.unit === unit);
      if (!service || !action) return;
      void runServisAction(service, action);
    });
  });
  grid.querySelectorAll<HTMLButtonElement>("[data-service-logs]").forEach((button) => {
    button.addEventListener("click", () => {
      const unit = button.dataset.serviceLogs || "";
      const service = services.find((item) => item.unit === unit);
      if (service) void loadServisGünlükler(service);
    });
  });
}

async function loadServisler(): Promise<void> {
  if (state.connection !== "online") {
    renderServisler();
    return;
  }
  try {
    setFilesStatus("");
    services = await invoke<ServisInfo[]>("service_list", {
      host: state.host, port: state.port, username: state.username, keyPath: state.keyPath,
    });
    renderServisCounts();
    renderServisler();
  } catch (error) {
    q<HTMLElement>("#services-grid").innerHTML = `<div class="panel empty-state-panel"><div class="placeholder-icon">!</div><h2>Servisler yüklenemedi</h2><p class="muted">${escapeHtml(String(error))}</p></div>`;
  }
}

async function runServisAction(service: ServisInfo, action: string): Promise<void> {
  const friendly = action === "restart" ? "restart" : action;
  if (!window.confirm(`${service.name} için ${friendly} işlemini çalıştırmak istiyor musun?`)) return;
  try {
    await invoke<string>("service_action", {
      host: state.host, port: state.port, username: state.username, keyPath: state.keyPath,
      service: service.unit.replace(/\.service$/, ""), action,
    });
    await loadServisler();
  } catch (error) {
    window.alert(`Servis işlemi başarısız:\n${String(error)}\n\nNot: Bu işlem kontrollü sudo yetkisi gerektirir.`);
  }
}

async function loadServisGünlükler(service: ServisInfo): Promise<void> {
  q<HTMLSelectElement>("#logs-service").value = service.unit.replace(/\.service$/, "");
  q<HTMLInputElement>("#logs-search").value = "";
  showPage("logs");
  await loadGünlükler();
}


type LogEntry = {
  raw: string;
  level: "error" | "warn" | "info" | "other";
};

let logsBusy = false;
let logsLive = false;
let logsEntries: LogEntry[] = [];
let unlistenGünlüklerOutput: UnlistenFn | null = null;
let unlistenGünlüklerHata: UnlistenFn | null = null;
let unlistenGünlüklerClosed: UnlistenFn | null = null;

function detectLogSeviye(line: string): LogEntry["level"] {
  const upper = line.toUpperCase();
  if (/\b(EMERG|ALERT|CRIT|CRITICAL|ERR|HATA|FAILED|FAILURE|FATAL)\b/.test(upper)) return "error";
  if (/\b(UYARI|UYARI|DEGRADED)\b/.test(upper)) return "warn";
  if (/\b(BİLGİ|NOTICE)\b/.test(upper)) return "info";
  return "other";
}

function renderGünlükler(): void {
  const level = q<HTMLSelectElement>("#logs-level").value;
  const search = q<HTMLInputElement>("#logs-search").value.trim().toLowerCase();
  const visible = logsEntries.filter((entry) => {
    const levelOk = level === "all" || entry.level === level;
    const searchOk = !search || entry.raw.toLowerCase().includes(search);
    return levelOk && searchOk;
  });
  q<HTMLElement>("#logs-output").textContent = visible.length ? visible.map((entry) => entry.raw).join("\n") : "Eşleşen günlük kaydı yok.";
  q<HTMLElement>("#logs-shown-count").textContent = String(visible.length);
  q<HTMLElement>("#logs-error-count").textContent = String(logsEntries.filter((e) => e.level === "error").length);
  q<HTMLElement>("#logs-warn-count").textContent = String(logsEntries.filter((e) => e.level === "warn").length);
  q<HTMLElement>("#logs-info-count").textContent = String(logsEntries.filter((e) => e.level === "info").length);
}

function updateGünlüklerTitle(): void {
  const service = q<HTMLSelectElement>("#logs-service").value;
  const labels: Record<string, string> = {
    all: "Tüm servisler", ssh: "SSH", docker: "Docker", nginx: "Nginx", mariadb: "MariaDB",
    "php8.5-fpm": "PHP 8.5 FPM", "armanc-node-api": "Armanc Node API",
    "armanc-python-api": "Armanc Python API", "jarvis-host-telemetry": "J.A.R.V.I.S Sunucu Telemetry",
  };
  q<HTMLElement>("#logs-output-title").textContent = labels[service] || service;
}

async function loadGünlükler(): Promise<void> {
  if (state.connection !== "online" || logsBusy) return;
  logsBusy = true;
  q<HTMLElement>("#logs-status-pill").textContent = "YÜKLENİYOR";
  q<HTMLElement>("#logs-status-pill").dataset.state = "loading";
  updateGünlüklerTitle();
  try {
    const service = q<HTMLSelectElement>("#logs-service").value;
    const since = q<HTMLSelectElement>("#logs-since").value;
    const lines = Number(q<HTMLSelectElement>("#logs-lines").value) || 100;
    const text = await invoke<string>("logs_query", {
      host: state.host, port: state.port, username: state.username, keyPath: state.keyPath,
      service, lines, sinceHours: since === "all" ? 0 : Number(since),
    });
    logsEntries = text.split(/\r?\n/).filter((line) => line.trim()).map((raw) => ({ raw, level: detectLogSeviye(raw) }));
    renderGünlükler();
    q<HTMLElement>("#logs-last-refresh").textContent = new Date().toLocaleTimeString();
    q<HTMLElement>("#logs-status-pill").textContent = q<HTMLButtonElement>("#logs-live-button").dataset.live === "true" ? "CANLI" : "HAZIR";
    q<HTMLElement>("#logs-status-pill").dataset.state = q<HTMLButtonElement>("#logs-live-button").dataset.live === "true" ? "live" : "ready";
  } catch (error) {
    logsEntries = [];
    q<HTMLElement>("#logs-output").textContent = `Günlük sorgusu başarısız:\n${String(error)}`;
    q<HTMLElement>("#logs-status-pill").textContent = "HATA";
    q<HTMLElement>("#logs-status-pill").dataset.state = "error";
  } finally {
    logsBusy = false;
  }
}

async function stopGünlüklerLive(): Promise<void> {
  logsLive = false;
  try {
    if (state.connection === "online") await invoke("stop_log_stream");
  } catch {
    // Ignore cleanup errors during disconnect/navigation.
  }
  const button = q<HTMLButtonElement>("#logs-live-button");
  button.dataset.live = "false";
  button.textContent = "● Canlı";
  q<HTMLElement>("#logs-status-pill").textContent = "HAZIR";
  q<HTMLElement>("#logs-status-pill").dataset.state = "ready";
}

async function startGünlüklerLive(): Promise<void> {
  if (state.connection !== "online") return;
  await stopGünlüklerLive();
  // Load the current window once, then keep a single persistent journalctl -f SSH session.
  await loadGünlükler();
  try {
    const service = q<HTMLSelectElement>("#logs-service").value;
    const lines = Number(q<HTMLSelectElement>("#logs-lines").value) || 100;
    await invoke("start_log_stream", {
      host: state.host, port: state.port, username: state.username, keyPath: state.keyPath,
      service, lines,
    });
    logsLive = true;
    const button = q<HTMLButtonElement>("#logs-live-button");
    button.dataset.live = "true";
    button.textContent = "■ Canlıyı Durdur";
    q<HTMLElement>("#logs-status-pill").textContent = "CANLI";
    q<HTMLElement>("#logs-status-pill").dataset.state = "live";
  } catch (error) {
    q<HTMLElement>("#logs-status-pill").textContent = "HATA";
    q<HTMLElement>("#logs-status-pill").dataset.state = "error";
    q<HTMLElement>("#logs-output").textContent += `\n\nGünlük akışı başarısız:\n${String(error)}`;
  }
}

let monitorStreamRunning = false;
let monitorStreamBuffer = "";
let unlistenMonitorOutput: UnlistenFn | null = null;
let unlistenMonitorHata: UnlistenFn | null = null;
const cpuHistory: number[] = [];
const memoryHistory: number[] = [];
const rxHistory: number[] = [];
const txHistory: number[] = [];
let previousNetwork: { rx: number; tx: number; at: number } | null = null;

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

function formatRate(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond)}/s`;
}

function pushHistory(target: number[], value: number, max = 60): void {
  target.push(Number.isFinite(value) ? Math.max(0, value) : 0);
  while (target.length > max) target.shift();
}

function drawTelemetryChart(canvas: HTMLCanvasElement, series: { values: number[]; label: string; kind: string }[], maxDeğer: number, suffix = "%"): void {
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const width = Math.max(300, Math.floor(rect.width));
  const height = 180;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#070b11";
  ctx.fillRect(0, 0, width, height);

  const pad = { l: 34, r: 12, t: 10, b: 24 };
  const w = width - pad.l - pad.r;
  const h = height - pad.t - pad.b;
  ctx.strokeStyle = "rgba(115,130,154,.14)";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i += 1) {
    const y = pad.t + (h * i / 4);
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(width - pad.r, y); ctx.stroke();
    ctx.fillStyle = "#566174"; ctx.font = "9px Cascadia Mono, Consolas, monospace";
    const value = maxDeğer - (maxDeğer * i / 4);
    ctx.fillText(`${value.toFixed(0)}${suffix}`, 5, y + 3);
  }

  series.forEach((item, index) => {
    const values = item.values;
    if (values.length < 2) return;
    ctx.beginPath();
    values.forEach((value, i) => {
      const x = pad.l + (w * i / Math.max(1, values.length - 1));
      const clamped = Math.min(maxDeğer, Math.max(0, value));
      const y = pad.t + h - (h * clamped / maxDeğer);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = index === 0 ? "#7b8fff" : "#52d891";
    ctx.lineWidth = 2;
    ctx.stroke();
  });
}

function drawNetworkChart(canvas: HTMLCanvasElement): void {
  const maxDeğer = Math.max(1024, ...rxHistory, ...txHistory);
  drawTelemetryChart(canvas, [
    { values: rxHistory, label: "RX", kind: "rx" },
    { values: txHistory, label: "TX", kind: "tx" },
  ], maxDeğer, "");
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.fillStyle = "#6e7d95";
  ctx.font = "9px Cascadia Mono, Consolas, monospace";
  ctx.fillText(formatRate(maxDeğer), Math.max(45, rect.width - 80), 15);
}

function renderMonitoring(data: MonitorSnapshot): void {
  state.monitor = data;
  q<HTMLElement>("#monitor-cpu").textContent = `${data.cpuPercent.toFixed(0)}%`;
  q<HTMLElement>("#monitor-memory").textContent = `${data.memoryPercent.toFixed(0)}%`;
  q<HTMLElement>("#monitor-disk").textContent = `${data.diskPercent.toFixed(0)}%`;
  q<HTMLElement>("#monitor-swap").textContent = `${data.swapPercent.toFixed(0)}%`;
  q<HTMLElement>("#monitor-cpu-detail").textContent = `${data.cpuPercent.toFixed(1)}% total CPU`;
  q<HTMLElement>("#monitor-memory-detail").textContent = `${formatBytes(data.memoryUsedBytes)} / ${formatBytes(data.memoryTotalBytes)}`;
  q<HTMLElement>("#monitor-disk-detail").textContent = `${formatBytes(data.diskUsedBytes)} used · ${formatBytes(data.diskFreeBytes)} free`;
  q<HTMLElement>("#monitor-swap-detail").textContent = `${formatBytes(data.swapUsedBytes)} / ${formatBytes(data.swapTotalBytes)}`;
  q<HTMLElement>("#monitor-cpu-bar").style.width = `${data.cpuPercent}%`;
  q<HTMLElement>("#monitor-memory-bar").style.width = `${data.memoryPercent}%`;
  q<HTMLElement>("#monitor-disk-bar").style.width = `${data.diskPercent}%`;
  q<HTMLElement>("#monitor-swap-bar").style.width = `${data.swapPercent}%`;
  q<HTMLElement>("#monitor-load1").textContent = data.load1.toFixed(2);
  q<HTMLElement>("#monitor-load5").textContent = data.load5.toFixed(2);
  q<HTMLElement>("#monitor-load15").textContent = data.load15.toFixed(2);
  q<HTMLElement>("#monitor-uptime").textContent = data.uptime;
  q<HTMLElement>("#monitor-temperature").textContent = data.temperature == null ? "—" : `${data.temperature.toFixed(1)} °C`;
  q<HTMLElement>("#monitor-processes").textContent = String(data.processCount);
  q<HTMLElement>("#monitor-network-interface").textContent = data.networkArayüz || "unknown";

  const now = performance.now();
  if (previousNetwork) {
    const dt = Math.max(0.25, (now - previousNetwork.at) / 1000);
    pushHistory(rxHistory, Math.max(0, data.rxBytes - previousNetwork.rx) / dt);
    pushHistory(txHistory, Math.max(0, data.txBytes - previousNetwork.tx) / dt);
  } else {
    pushHistory(rxHistory, 0); pushHistory(txHistory, 0);
  }
  previousNetwork = { rx: data.rxBytes, tx: data.txBytes, at: now };
  pushHistory(cpuHistory, data.cpuPercent);
  pushHistory(memoryHistory, data.memoryPercent);

  drawTelemetryChart(q<HTMLCanvasElement>("#monitor-cpu-chart"), [
    { values: cpuHistory, label: "CPU", kind: "cpu" },
    { values: memoryHistory, label: "RAM", kind: "memory" },
  ], 100);
  drawNetworkChart(q<HTMLCanvasElement>("#monitor-network-chart"));

  const process = data.topİşlem;
  q<HTMLElement>("#monitor-top-process").innerHTML = process
    ? `<div class="top-process-row"><div><strong>${escapeHtml(process.command)}</strong><span>PID ${process.pid}</span></div><div><strong>${process.cpuPercent.toFixed(1)}%</strong><span>CPU</span></div><div><strong>${process.memoryPercent.toFixed(1)}%</strong><span>MEM</span></div></div>`
    : '<div class="muted">İşlem verisi yok.</div>';
}

function resetMonitoringDisplay(): void {
  monitorStreamRunning = false;
  monitorStreamBuffer = "";
  previousNetwork = null;
  cpuHistory.length = 0;
  memoryHistory.length = 0;
  rxHistory.length = 0;
  txHistory.length = 0;
  ["#monitor-cpu", "#monitor-memory", "#monitor-disk", "#monitor-swap", "#monitor-load1", "#monitor-load5", "#monitor-load15", "#monitor-uptime", "#monitor-temperature", "#monitor-processes", "#monitor-network-interface"].forEach((selector) => setTextIfPresent(selector, "—"));
  setTextIfPresent("#monitor-live-pill", "AKIŞ KAPALI");
  setTextIfPresent("#monitor-top-process", "Bağlantı verisi yok.");
}

function monitorSnapshotFromSatır(lines: string[]): MonitorSnapshot | null {
  const values = new Map<string, string>();
  for (const line of lines) {
    const first = line.indexOf("__");
    if (first < 0) continue;
    const second = line.indexOf("__", first + 2);
    if (second < 0) continue;
    const key = line.slice(first, second + 2);
    const value = line.slice(second + 2).trim();
    values.set(key, value);
  }
  const nums = (key: string): number[] => {
    const value = values.get(key) || "";
    return value.split(/\s+/).filter(Boolean).map(Number).filter(Number.isFinite);
  };
  const mem = nums("__JMEM__");
  const swap = nums("__JSWAP__");
  const disk = nums("__JDISK__");
  const load = nums("__JLOAD__");
  const net = nums("__JNET__");
  const top = (() => {
    const value = values.get("__JTOP__") || "";
    const parts = value.split(/\s+/);
    if (parts.length < 4) return null;
    const pid = Number(parts[0]);
    const cpu = Number(parts[parts.length - 2]);
    const memory = Number(parts[parts.length - 1]);
    const command = parts.slice(1, -2).join(" ");
    if (!Number.isFinite(pid) || !Number.isFinite(cpu) || !Number.isFinite(memory) || !command) return null;
    return { pid, command, cpuPercent: cpu, memoryPercent: memory };
  })();

  const cpu = Number(values.get("__JCPU__") || 0);
  const uptimeSeconds = Number(values.get("__JUPTIME__") || 0);
  const processCount = Number(values.get("__JPROC__") || 0);
  if (!Number.isFinite(cpu)) return null;

  return {
    cpuPercent: cpu,
    memoryPercent: mem[2] || 0,
    memoryUsedBytes: mem[0] || 0,
    memoryTotalBytes: mem[1] || 0,
    swapPercent: swap[2] || 0,
    swapUsedBytes: swap[0] || 0,
    swapTotalBytes: swap[1] || 0,
    diskPercent: disk[3] || 0,
    diskUsedBytes: disk[0] || 0,
    diskTotalBytes: disk[1] || 0,
    diskFreeBytes: disk[2] || 0,
    load1: load[0] || 0,
    load5: load[1] || 0,
    load15: load[2] || 0,
    uptimeSeconds: Number.isFinite(uptimeSeconds) ? uptimeSeconds : 0,
    uptime: values.get("__JUPTIMEPRETTY__") || "unknown",
    temperature: (() => { const t = Number(values.get("__JTEMP__") || 0); return Number.isFinite(t) && t > 0 ? t : null; })(),
    networkArayüz: values.get("__JIFACE__") || "unknown",
    rxBytes: net[0] || 0,
    txBytes: net[1] || 0,
    processCount: Number.isFinite(processCount) ? processCount : 0,
    topİşlem: top,
  };
}

function handleMonitorStreamLine(line: string): void {
  if (line === "__JMON_END__") {
    const snapshot = monitorSnapshotFromSatır(monitorStreamBuffer.split("\n").filter(Boolean));
    monitorStreamBuffer = "";
    if (!snapshot) return;
    renderMonitoring(snapshot);
    q<HTMLElement>("#monitor-live-pill").textContent = `STREAM · ${new Date().toLocaleTimeString()}`;
    return;
  }
  if (line.trim()) {
    monitorStreamBuffer += `${line}\n`;
  }
}

async function ensureMonitorListeners(): Promise<void> {
  const tasks: Promise<void>[] = [];
  if (!unlistenMonitorOutput) {
    tasks.push(listen<string>("monitor-output", (event) => handleMonitorStreamLine(event.payload)).then((unlisten) => {
      unlistenMonitorOutput = unlisten;
    }));
  }
  if (!unlistenMonitorHata) {
    tasks.push(listen<string>("monitor-error", (event) => {
      if (!monitorStreamRunning) return;
      const message = event.payload.trim();
      if (!message) return;
      q<HTMLElement>("#monitor-live-pill").textContent = "AKIŞ HATASI";
      q<HTMLElement>("#monitor-top-process").innerHTML = `<div class="muted">${escapeHtml(message)}</div>`;
    }).then((unlisten) => {
      unlistenMonitorHata = unlisten;
    }));
  }
  await Promise.all(tasks);
}

async function startMonitoring(): Promise<void> {
  if (state.connection !== "online") return;
  stopMonitoring(false);
  await ensureMonitorListeners();
  // Durdur the previous stream first so its close event cannot race the new stream.
  try {
    await invoke("stop_monitor_stream");
  } catch {
    // No active stream is fine.
  }
  monitorStreamBuffer = "";
  monitorStreamRunning = false;
  q<HTMLElement>("#monitor-live-pill").textContent = "AKIŞ BAŞLIYOR";
  try {
    const interval = Math.min(30, Math.max(2, Number(q<HTMLSelectElement>("#monitor-interval").value) || 5));
    await invoke("start_monitor_stream", {
      host: state.host,
      port: state.port,
      username: state.username,
      keyPath: state.keyPath,
      intervalSeconds: interval,
    });
    monitorStreamRunning = true;
    q<HTMLElement>("#monitor-live-pill").textContent = `STREAM · ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    monitorStreamRunning = false;
    q<HTMLElement>("#monitor-live-pill").textContent = "AKIŞ HATASI";
    q<HTMLElement>("#monitor-top-process").innerHTML = `<div class="muted">${escapeHtml(String(error))}</div>`;
  }
}

function stopMonitoring(restartCleanup = true): void {
  monitorStreamRunning = false;
  monitorStreamBuffer = "";
  if (restartCleanup && state.connection === "online") {
    void invoke("stop_monitor_stream").catch(() => undefined);
  }
  q<HTMLElement>("#monitor-live-pill").textContent = "AKIŞ KAPALI";
}

function refreshMonitoring(): void {
  if (document.querySelector("#page-monitoring")?.classList.contains("active-page")) {
    void startMonitoring();
  }
}

function securityDurumPill(el: HTMLElement, state: string): void {
  const normalized = state.toLowerCase();
  const labels: Record<string, string> = {
    pass: "BAŞARILI", active: "ETKİN", secure: "GÜVENLİ", warn: "UYARI", medium: "ORTA", fail: "BAŞARISIZ", critical: "KRİTİK", high: "YÜKSEK", inactive: "DEVRE DIŞI", unknown: "BİLİNMİYOR", review: "İNCELE", exposed: "AÇIK", protected: "KORUMALI", "local only": "YALNIZCA YEREL"
  };
  el.textContent = labels[normalized] || state;
  el.dataset.state = ["pass", "active", "secure", "protected", "local only"].includes(normalized) ? "ok" : ["fail", "critical", "high", "exposed"].includes(normalized) ? "error" : ["warn", "medium", "review"].includes(normalized) ? "warn" : "unknown";
}

function translateSecurityState(state: SecurityCheck["state"]): string {
  return ({ PASS: "BAŞARILI", WARN: "UYARI", FAIL: "BAŞARISIZ", INFO: "BİLGİ", UNKNOWN: "BİLİNMİYOR" } as Record<SecurityCheck["state"], string>)[state];
}

function translateSecuritySeverity(severity: SecurityFinding["severity"]): string {
  return ({ CRITICAL: "KRİTİK", HIGH: "YÜKSEK", MEDIUM: "ORTA", LOW: "DÜŞÜK", INFO: "BİLGİ" } as Record<SecurityFinding["severity"], string>)[severity];
}

function translateSecurityText(value: string): string {
  const map: Array<[string, string]> = [
    ["SSH password authentication is enabled", "SSH parola kimlik doğrulaması etkin."],
    ["SSH public-key authentication is disabled", "SSH açık anahtar kimlik doğrulaması devre dışı."],
    ["Direct root SSH login is enabled", "Doğrudan root SSH girişi etkin."],
    ["Direct root SSH login is restricted, not disabled", "Doğrudan root SSH girişi kısıtlanmış, ancak tamamen devre dışı değil."],
    ["MaxAuthTries is relatively high", "MaxAuthTries değeri görece yüksek."],
    ["X11 forwarding is enabled", "X11 yönlendirmesi etkin."],
    ["UFW firewall is inactive", "UFW güvenlik duvarı devre dışı."],
    ["Fail2Ban is inactive", "Fail2Ban devre dışı."],
    ["Listening services require review", "Dinleyen servislerin incelenmesi gerekiyor."],
    ["SSH is listening on port 22", "SSH 22 numaralı portu dinliyor."],
    ["Security audit has incomplete checks", "Güvenlik denetiminde tamamlanmamış kontroller var."],
    ["Password-based SSH authentication is disabled.", "Parola tabanlı SSH kimlik doğrulaması devre dışı."],
    ["Public-key authentication is enabled.", "Açık anahtar kimlik doğrulaması etkin."],
    ["Direct SSH root login is disabled.", "Doğrudan SSH root girişi devre dışı."],
    ["Authentication attempts are bounded.", "Kimlik doğrulama denemeleri sınırlandırılmış."],
    ["X11 forwarding is disabled.", "X11 yönlendirmesi devre dışı."],
    ["UFW is active.", "UFW etkin."],
    ["Fail2Ban is active.", "Fail2Ban etkin."],
    ["The daemon accepts password authentication in addition to key-based access.", "Sunucu anahtar erişimine ek olarak parola kimlik doğrulamasını kabul ediyor."],
    ["The server is not configured to accept SSH public keys.", "Sunucu SSH açık anahtarlarını kabul edecek şekilde yapılandırılmamış."],
    ["Direct root login is restricted to public-key authentication.", "Doğrudan root girişi yalnızca açık anahtar kimlik doğrulamasıyla kısıtlanmış."],
    ["Authentication attempts are bounded.", "Kimlik doğrulama denemeleri sınırlandırılmış."],
    ["The authentication attempt limit is higher than recommended for a small server.", "Kimlik doğrulama deneme limiti küçük bir sunucu için önerilenden yüksek."],
    ["The local firewall is not active according to the audit.", "Denetime göre yerel güvenlik duvarı etkin değil."],
    ["The intrusion-prevention service is not active.", "Saldırı önleme servisi etkin değil."],
    ["Some non-local listeners still need service or exposure review.", "Bazı yerel olmayan dinleyicilerin servis ve maruziyet açısından incelenmesi gerekiyor."],
    ["Non-local listeners are present but no unclassified listener requires review.", "Yerel olmayan dinleyiciler mevcut ancak sınıflandırılmamış dinleyici bulunmuyor."],
    ["Non-local listeners are protected by the detected UFW/default firewall policy or are otherwise classified.", "Yerel olmayan dinleyiciler tespit edilen UFW/varsayılan güvenlik duvarı politikasıyla korunuyor veya sınıflandırılmış durumda."],
    ["No non-local listeners were detected.", "Yerel olmayan dinleyici tespit edilmedi."],
    ["Changing the SSH port is not a substitute for firewall and authentication controls.", "SSH portunu değiştirmek güvenlik duvarı ve kimlik doğrulama kontrollerinin yerine geçmez."],
  ];
  for (const [from, to] of map) if (value === from || value.startsWith(from)) return value === from ? to : to + value.slice(from.length);
  return value;
}

function renderSecurityCheck(target: string, checks: SecurityCheck[]): void {
  const el = q<HTMLElement>(target);
  el.innerHTML = checks.length ? checks.map(c => `<div class="security-check-card"><div class="security-check-top"><span>${escapeHtml(translateSecurityText(c.label))}</span><strong data-state="${c.state.toLowerCase()}">${escapeHtml(translateSecurityState(c.state))}</strong></div><b>${escapeHtml(translateSecurityText(c.value))}</b><small>${escapeHtml(translateSecurityText(c.detail))}</small></div>`).join("") : `<div class="empty-state">Kontrol bulunamadı.</div>`;
}

function listenerStatusClass(status: string): string {
  switch (status) {
    case "SAFE":
    case "PROTECTED": return "ok";
    case "CONTAINER":
    case "EXPOSED": return "info";
    case "KNOWN SERVICE": return "warn";
    default: return "error";
  }
}

function listenerKapsamClass(scope: string): string {
  if (scope === "LOCAL ONLY") return "ok";
  if (scope === "LAN / PRIVATE") return "info";
  if (scope === "ALL INTERFACES") return "warn";
  return "error";
}

function renderSecurityListeners(listeners: SecurityListener[]): void {
  const el = q<HTMLElement>("#security-listener-table");
  if (!listeners.length) {
    el.innerHTML = `<div class="empty-state">Denetim hiçbir dinleme soketi döndürmedi.</div>`;
    return;
  }
  el.innerHTML = `<table class="security-listener-table"><thead><tr><th>Uç Nokta</th><th>İşlem / Birim</th><th>Kapsam</th><th>Servis</th><th>Maruziyet</th><th>Firewall</th><th>Değerlendirme</th></tr></thead><tbody>${listeners.map(l => {
    const endpoint = `${l.address}:${l.port}`;
    const proc = l.pid ? `${l.process} · PID ${l.pid}` : l.process;
    const unit = l.unit ? `<small>${escapeHtml(l.unit)}</small>` : "";
    const exposureClass = l.exposure === "PROTECTED" || l.exposure === "LOCAL" ? "ok" : l.exposure === "EXPOSED" ? "info" : "warn";
    const firewallClass = l.firewall.includes("ALLOWED") ? "warn" : l.firewall.includes("BLOCKED") || l.firewall.includes("DENIED") ? "ok" : "info";
    return `<tr>
      <td><strong>${escapeHtml(endpoint)}</strong><small>${escapeHtml(l.protocol.toUpperCase())}</small></td>
      <td>${escapeHtml(proc)}${unit}</td>
      <td><span class="listener-badge ${listenerKapsamClass(l.scope)}">${escapeHtml(l.scope)}</span></td>
      <td>${escapeHtml(l.service)}</td>
      <td><span class="listener-badge ${exposureClass}">${escapeHtml(l.exposure)}</span></td>
      <td><span class="listener-firewall ${firewallClass}">${escapeHtml(l.firewall)}</span></td>
      <td><span class="listener-badge ${listenerStatusClass(l.status)}">${escapeHtml(l.status)}</span></td>
    </tr>`;
  }).join("")}</tbody></table>`;
}
function renderSecurityAudit(data: SecurityAudit): void {
  q<HTMLElement>("#security-score").textContent = String(data.score);
  q<HTMLElement>("#security-grade").textContent = data.grade;
  q<HTMLElement>("#security-score-bar").style.width = `${Math.max(0, Math.min(100, data.score))}%`;
  const failed = data.findings.filter(f => f.severity === "CRITICAL" || f.severity === "HIGH").length;
  const unknown = data.checks.filter(c => c.state === "UNKNOWN").length;
  q<HTMLElement>("#security-score-detail").textContent = failed
    ? `${failed} high-impact finding(s) require attention.`
    : unknown
      ? `${unknown} check(s) are incomplete; score is adjusted for uncertainty.`
      : "No critical or high-impact finding detected by this audit.";
  const generatedDate = data.generatedAt.startsWith("unix:") ? new Date(Number(data.generatedAt.slice(5)) * 1000) : new Date(data.generatedAt);
  const generatedLabel = Number.isNaN(generatedDate.getTime()) ? "time unavailable" : generatedDate.toLocaleTimeString();
  q<HTMLElement>("#security-meta").textContent = `SSH ${data.sshPort} · External listeners ${data.externalListeningPorts} · ${generatedLabel}`;

  const sshChecks = data.checks.filter(c => ["password_auth", "pubkey_auth", "root_login", "max_auth_tries", "x11_forwarding"].includes(c.key));
  const ufwChecks = data.checks.filter(c => c.key.startsWith("ufw_"));
  const f2bChecks = data.checks.filter(c => c.key.startsWith("f2b_"));
  renderSecurityCheck("#security-ssh-checks", sshChecks);
  renderSecurityCheck("#security-ufw-checks", ufwChecks);
  renderSecurityCheck("#security-f2b-checks", f2bChecks);

  const sshChecksHaveUnknown = sshChecks.some(c => c.state === "UNKNOWN");
  const sshChecksHaveFail = sshChecks.some(c => c.state === "FAIL");
  securityDurumPill(q<HTMLElement>("#security-ssh-pill"), sshChecksHaveFail ? "WARN" : sshChecksHaveUnknown ? "UNKNOWN" : "PASS");
  securityDurumPill(q<HTMLElement>("#security-ufw-pill"), data.ufwActive === true ? "ACTIVE" : data.ufwActive === false ? "INACTIVE" : "UNKNOWN");
  securityDurumPill(q<HTMLElement>("#security-f2b-pill"), data.fail2banActive === true ? "ACTIVE" : data.fail2banActive === false ? "INACTIVE" : "UNKNOWN");
  securityDurumPill(q<HTMLElement>("#security-port-pill"), data.reviewListenerPorts > 0 ? `${data.reviewListenerPorts} REVIEW` : data.exposedListenerPorts > 0 ? `${data.exposedListenerPorts} EXPOSED` : data.externalListeningPorts > 0 ? `${data.protectedListenerPorts} PROTECTED` : "LOCAL ONLY");

  q<HTMLElement>("#security-exposure").textContent = data.externalListeningPorts > 0
    ? `${data.externalListeningPorts} non-local listener(s): ${data.exposedListenerPorts} exposed · ${data.protectedListenerPorts} protected · ${data.reviewListenerPorts} review. J.A.R.V.I.S correlates bind scope, service ownership and UFW policy before any blocking action.`
    : "No externally bound listening sockets were detected by the audit.";

  renderSecurityListeners(data.listeners || []);

  q<HTMLElement>("#security-finding-count").textContent = `${data.findings.length} finding${data.findings.length === 1 ? "" : "s"}`;
  q<HTMLElement>("#security-findings").innerHTML = data.findings.length ? data.findings.map((f, idx) => { const preview = getSecurityFixPreview(f); const actionLabel = preview?.mode === "REVIEW" ? "İncele" : "Düzeltmeyi Hazırla"; return `<div class="security-finding" data-severity="${f.severity.toLowerCase()}"><div><div class="finding-head"><span class="finding-severity">${escapeHtml(translateSecuritySeverity(f.severity))}</span><button class="mini-action" data-fix-index="${idx}">${actionLabel}</button></div><h3>${escapeHtml(translateSecurityText(f.title))}</h3><p>${escapeHtml(translateSecurityText(f.detail))}</p><small><b>Öneri:</b> ${escapeHtml(translateSecurityText(f.recommendation))}</small></div></div>`; }).join("") : `<div class="empty-state">Bulgu yok. Mevcut denetim kontrolleri başarılı.</div>`;
  document.querySelectorAll<HTMLButtonElement>("[data-fix-index]").forEach(btn => btn.addEventListener("click", () => prepareSecurityFix(data.findings[Number(btn.dataset.fixIndex)])));

  q<HTMLElement>("#security-checks").innerHTML = data.checks.length ? `<table class="remote-table"><thead><tr><th>Kontrol</th><th>Durum</th><th>Değer</th><th>Ayrıntı</th></tr></thead><tbody>${data.checks.map(c => `<tr><td><strong>${escapeHtml(c.label)}</strong></td><td>${escapeHtml(c.state)}</td><td>${escapeHtml(c.value)}</td><td>${escapeHtml(c.detail)}</td></tr>`).join("")}</tbody></table>` : `<div class="empty-state">Kontrol bulunamadı.</div>`;
}

function clearSecurityAuditDisplay(): void {
  setTextIfPresent("#security-score", "—");
  setTextIfPresent("#security-grade", "DOĞRULANAMADI");
  const scoreBar = document.querySelector<HTMLElement>("#security-score-bar");
  if (scoreBar) scoreBar.style.width = "0%";
  setTextIfPresent("#security-score-detail", "Bağlantı kapandığı için önceki denetim verisi temizlendi.");
  setTextIfPresent("#security-meta", "Doğrulanmış denetim yok.");
  setTextIfPresent("#security-exposure", "Bağlantı kapandığı için dinleme yüzeyi doğrulanamıyor.");
  setTextIfPresent("#security-finding-count", "0 bulgu");
  ["#security-ssh-checks", "#security-ufw-checks", "#security-f2b-checks", "#security-checks", "#security-findings", "#security-listener-table"].forEach((selector) => {
    const element = document.querySelector<HTMLElement>(selector);
    if (element) element.innerHTML = '<div class="empty-state">Doğrulanmış bağlantı verisi yok.</div>';
  });
  ["#security-ssh-pill", "#security-ufw-pill", "#security-f2b-pill", "#security-port-pill"].forEach((selector) => {
    const pill = document.querySelector<HTMLElement>(selector);
    if (pill) {
      pill.textContent = "DOĞRULANAMADI";
      pill.dataset.state = "unknown";
    }
  });
}

type SecurityFixPreview = { id: "disable_password_auth" | "disable_root_login" | "disable_x11_forwarding" | "review_external_listeners" | "review_ssh_port"; title: string; current: string; proposed: string; impact: string; rollback: string; risk: "LOW" | "MEDIUM" | "HIGH" | "INFO"; mode: "FIX" | "REVIEW"; };

function getSecurityFixPreview(finding: SecurityFinding): SecurityFixPreview | null {
  const title = finding.title.toLowerCase();
  if (title.includes("password authentication")) {
    return {
      id: "disable_password_auth",
      title: "Disable SSH password authentication",
      current: "PasswordAuthentication yes",
      proposed: "PasswordAuthentication no",
      impact: "New SSH logins will require an accepted public-key authentication method. Existing sessions are not forcibly terminated.",
      rollback: "Restore the backed-up SSH configuration if password authentication is intentionally required.",
      risk: "HIGH",
      mode: "FIX",
    };
  }
  if (title.includes("root ssh login")) {
    return {
      id: "disable_root_login",
      title: "Disable direct SSH root login",
      current: finding.detail || "PermitRootLogin prohibit-password",
      proposed: "PermitRootLogin no",
      impact: "Direct root SSH logins will be rejected. Administrative access should continue through a normal account with sudo.",
      rollback: "Restore the backed-up SSH configuration if direct root SSH access is explicitly required.",
      risk: "MEDIUM",
      mode: "FIX",
    };
  }
  if (title.includes("x11 forwarding")) {
    return {
      id: "disable_x11_forwarding",
      title: "Disable SSH X11 forwarding",
      current: "X11Forwarding yes",
      proposed: "X11Forwarding no",
      impact: "SSH X11 forwarding will no longer be available for new sessions.",
      rollback: "Restore the backed-up SSH configuration if GUI forwarding is intentionally required.",
      risk: "LOW",
      mode: "FIX",
    };
  }
  if (title.includes("externally bound listening services")) {
    return {
      id: "review_external_listeners",
      title: "İncele externally bound listening services",
      current: finding.detail,
      proposed: "No blanket firewall change",
      impact: "External listeners may be intentional LAN/public services. Blindly blocking them could break Docker, web, database, API, or other workloads.",
      rollback: "No server change is proposed. İncele each listener and its UFW policy before creating a targeted rule.",
      risk: "MEDIUM",
      mode: "REVIEW",
    };
  }
  if (title.includes("ssh is listening on port 22")) {
    return {
      id: "review_ssh_port",
      title: "İncele SSH listening on port 22",
      current: "SSH port 22",
      proposed: "No change",
      impact: "Port 22 is the standard SSH port and is not itself a security failure.",
      rollback: "No server change is proposed. Keep port 22 if it matches your network policy.",
      risk: "INFO",
      mode: "REVIEW",
    };
  }
  return null;
}

let activeSecurityFix: { preview: SecurityFixPreview; backupPath: string; applied: boolean } | null = null;

async function loadSecurityEffectiveDurum(): Promise<SecurityAudit | null> {
  if (state.connection !== "online") return null;
  try {
    const data = await invoke<SecurityAudit>("security_audit", { host: state.host, port: state.port, username: state.username, keyPath: state.keyPath });
    return data;
  } catch {
    return null;
  }
}

async function applySecurityFix(): Promise<void> {
  if (!activeSecurityFix || activeSecurityFix.preview.mode !== "FIX" || state.connection !== "online") return;
  const resultEl = q<HTMLElement>("#security-fix-result");
  const applyButton = q<HTMLButtonElement>("#security-fix-apply-button");
  const rollbackButton = q<HTMLButtonElement>("#security-fix-rollback-button");
  if (!window.confirm(`${activeSecurityFix.preview.title} uygulanacak. /etc/ssh için yedek alınacak ve ssh servisi reload edilecek. Devam edilsin mi?`)) return;
  applyButton.disabled = true;
  rollbackButton.hidden = true;
  resultEl.removeAttribute("data-state");
  resultEl.textContent = "Güvenlik düzeltmesi uygulanıyor…";
  try {
    const result = await invoke<{ id: string; backupPath: string; action: string; message: string }>("security_apply_fix", {
      host: state.host,
      port: state.port,
      username: state.username,
      keyPath: state.keyPath,
      fixId: activeSecurityFix.preview.id,
    });
    if (!result.id.trim() || !result.backupPath.trim() || !result.action.trim() || !result.message.trim()) {
      throw new Error("Güvenlik helper'ı doğrulanabilir, eksiksiz bir sonuç döndürmedi.");
    }
    const refreshed = await loadSecurityEffectiveDurum();
    if (!refreshed || securityFixIsRequired(refreshed, activeSecurityFix.preview.id)) {
      activeSecurityFix.applied = false;
      throw new Error("Düzeltme sonrası etkin yapılandırma yeniden doğrulanamadı.");
    }
    activeSecurityFix.backupPath = result.backupPath;
    activeSecurityFix.applied = true;
    resultEl.dataset.state = "ok";
    resultEl.textContent = `${result.message}\nBackup: ${result.backupPath}`;

    q<HTMLElement>("#security-fix-current").textContent = activeSecurityFix.preview.proposed;
    q<HTMLElement>("#security-fix-risk").textContent = "UYGULANDI · DOĞRULANDI";
    q<HTMLElement>("#security-fix-risk").dataset.state = "ok";
    rollbackButton.hidden = false;
    applyButton.hidden = true;
    applyButton.disabled = true;

    renderSecurityAudit(refreshed);
  } catch (error) {
    resultEl.dataset.state = "error";
    resultEl.textContent = `Fix başarısız: ${String(error)}`;
  } finally {
    applyButton.disabled = false;
  }
}

async function rollbackSecurityFix(): Promise<void> {
  if (!activeSecurityFix?.backupPath || state.connection !== "online") return;
  const resultEl = q<HTMLElement>("#security-fix-result");
  const rollbackButton = q<HTMLButtonElement>("#security-fix-rollback-button");
  if (!window.confirm("J.A.R.V.I.S tarafından alınan SSH yedeği geri yüklenecek. Devam edilsin mi?")) return;
  rollbackButton.disabled = true;
  resultEl.removeAttribute("data-state");
  resultEl.textContent = "Geri alma uygulanıyor…";
  try {
    const message = await invoke<string>("security_rollback", {
      host: state.host,
      port: state.port,
      username: state.username,
      keyPath: state.keyPath,
      backupPath: activeSecurityFix.backupPath,
    });
    if (!message.trim()) {
      throw new Error("Geri alma helper'ı boş sonuç döndürdü.");
    }
    const refreshed = await loadSecurityEffectiveDurum();
    if (!refreshed || !securityFixIsRequired(refreshed, activeSecurityFix.preview.id)) {
      throw new Error("Geri alma sonrası etkin yapılandırma yeniden doğrulanamadı.");
    }
    resultEl.dataset.state = "ok";
    resultEl.textContent = message;
    rollbackButton.hidden = true;
    if (activeSecurityFix) activeSecurityFix.applied = false;
    renderSecurityAudit(refreshed);
  } catch (error) {
    resultEl.dataset.state = "error";
    resultEl.textContent = `Geri Al başarısız: ${String(error)}`;
  } finally {
    rollbackButton.disabled = false;
  }
}

function securityFixIsRequired(data: SecurityAudit, fixId: SecurityFixPreview["id"]): boolean {
  if (fixId === "disable_password_auth") return data.passwordAuthentication === true;
  if (fixId === "disable_root_login") return data.permitRootLogin !== "no" && data.permitRootLogin !== "unknown";
  if (fixId === "disable_x11_forwarding") return data.x11Forwarding === true;
  return false;
}

function syncActiveSecurityFix(data: SecurityAudit): void {
  const active = activeSecurityFix;
  if (!active || active.preview.mode !== "FIX") return;

  const required = securityFixIsRequired(data, active.preview.id);
  const currentEl = q<HTMLElement>("#security-fix-current");
  const riskEl = q<HTMLElement>("#security-fix-risk");
  const applyButton = q<HTMLButtonElement>("#security-fix-apply-button");
  const rollbackButton = q<HTMLButtonElement>("#security-fix-rollback-button");

  if (!required) {
    active.applied = true;
    currentEl.textContent = active.preview.proposed;
    riskEl.textContent = "APPLIED · SECURE";
    riskEl.dataset.state = "ok";
    applyButton.hidden = true;
    applyButton.disabled = true;
    rollbackButton.hidden = !active.backupPath;
  } else {
    active.applied = false;
    if (active.preview.id === "disable_password_auth") currentEl.textContent = `PasswordAuthentication ${data.passwordAuthentication === false ? "no" : data.passwordAuthentication === true ? "yes" : "unknown"}`;
    if (active.preview.id === "disable_root_login") currentEl.textContent = `PermitRootLogin ${data.permitRootLogin || "unknown"}`;
    if (active.preview.id === "disable_x11_forwarding") currentEl.textContent = `X11Forwarding ${data.x11Forwarding === true ? "yes" : "unknown"}`;
    riskEl.textContent = `${active.preview.risk} RISK · HAZIR TO APPLY`;
    riskEl.dataset.state = active.preview.risk.toLowerCase();
    applyButton.hidden = false;
    applyButton.disabled = false;
    rollbackButton.hidden = true;
  }
}

function prepareSecurityFix(finding: SecurityFinding): void {
  const preview = getSecurityFixPreview(finding);
  if (!preview) {
    alert("Bu bulgu için güvenli bir otomatik işlem tanımlı değil. Önce manuel inceleme gerekiyor.");
    return;
  }
  activeSecurityFix = { preview, backupPath: "", applied: false };
  q<HTMLElement>("#security-fix-modal-title").textContent = preview.title;
  q<HTMLElement>("#security-fix-modal-heading").textContent = preview.mode === "REVIEW" ? "GÜVENLİK REVIEW" : "GÜVENLİK DÜZELTMESİ";
  q<HTMLElement>("#security-fix-current").textContent = preview.current;
  q<HTMLElement>("#security-fix-proposed").textContent = preview.proposed;
  q<HTMLElement>("#security-fix-impact").textContent = preview.impact;
  q<HTMLElement>("#security-fix-rollback").textContent = preview.rollback;
  q<HTMLElement>("#security-fix-risk").textContent = preview.mode === "REVIEW" ? `${preview.risk} RISK · MANUAL REVIEW` : `${preview.risk} RISK · HAZIR TO APPLY`;
  q<HTMLElement>("#security-fix-risk").dataset.state = preview.risk.toLowerCase();
  const applyButton = q<HTMLButtonElement>("#security-fix-apply-button");
  const rollbackButton = q<HTMLButtonElement>("#security-fix-rollback-button");
  applyButton.hidden = preview.mode !== "FIX";
  applyButton.disabled = false;
  rollbackButton.hidden = true;
  q<HTMLElement>("#security-fix-warning").textContent = preview.mode === "FIX"
    ? "Bu işlem J.A.R.V.I.S remediation helper üzerinden çalışır, yalnızca yönetilen SSH dosyasının mevcut halini yedekler, tanımlı direktifi değiştirir, sshd -t ile doğrular ve ssh servisini reload eder. Doğrulama başarısız olursa otomatik rollback yapılır."
    : "Bu panel yalnızca inceleme içindir. Sunucuda otomatik değişiklik yapılmaz.";
  q<HTMLElement>("#security-fix-result").textContent = "";
  q<HTMLElement>("#security-fix-result").removeAttribute("data-state");
  q<HTMLElement>("#security-fix-modal").classList.add("open");
}

function closeSecurityFixPreview(): void {
  activeSecurityFix = null;
  q<HTMLElement>("#security-fix-modal").classList.remove("open");
}

async function loadSecurityAudit(): Promise<SecurityAudit | null> {
  if (state.connection !== "online") return null;
  const button = q<HTMLButtonElement>("#security-refresh-button");
  button.disabled = true;
  try {
    const data = await invoke<SecurityAudit>("security_audit", { host: state.host, port: state.port, username: state.username, keyPath: state.keyPath });
    renderSecurityAudit(data);
    if (!activeSecurityFix?.applied) syncActiveSecurityFix(data);
    return data;
  } catch (error) {
    q<HTMLElement>("#security-findings").innerHTML = `<div class="empty-state">Güvenlik denetimi başarısız: ${escapeHtml(String(error))}</div>`;
    return null;
  } finally { button.disabled = state.connection !== "online"; }
}

async function loadRemoteAccess(): Promise<void> {
  if (state.connection !== "online") return;
  const button = q<HTMLButtonElement>("#remote-refresh-button");
  button.disabled = true;
  try {
    const data = await invoke<RemoteAccessSnapshot>("remote_access_snapshot", { host: state.host, port: state.port, username: state.username, keyPath: state.keyPath });
    state.remote = data;
    q<HTMLElement>("#remote-host").textContent = state.host;
    q<HTMLElement>("#remote-port").textContent = String(data.sshPort || state.port);
    q<HTMLElement>("#remote-user").textContent = state.username;
    q<HTMLElement>("#remote-auth").textContent = data.authMethod || "publickey";
    const sshP = q<HTMLElement>("#remote-ssh-status"); sshP.textContent = "CONNECTED"; sshP.dataset.state = "ok";
    const ufwP = q<HTMLElement>("#remote-ufw-status"); ufwP.textContent = data.ufwActive == null ? "UNKNOWN" : data.ufwActive ? "ACTIVE" : "INACTIVE"; ufwP.dataset.state = data.ufwActive ? "ok" : data.ufwActive === false ? "warn" : "unknown";
    q<HTMLElement>("#remote-ufw-output").textContent = data.ufwOutput || "UFW status unavailable.";
    q<HTMLElement>("#remote-ufw-rules").textContent = String(data.ufwRuleCount ?? 0);
    q<HTMLElement>("#remote-ufw-detail-state").textContent = (data.ufwOutput || "").toLowerCase().includes("passwordless sudo") ? "LIMITED" : "MEVCUT";
    const f2bP = q<HTMLElement>("#remote-f2b-status"); f2bP.textContent = data.fail2banActive == null ? "UNKNOWN" : data.fail2banActive ? "ACTIVE" : "INACTIVE"; f2bP.dataset.state = data.fail2banActive ? "ok" : data.fail2banActive === false ? "warn" : "unknown";
    q<HTMLElement>("#remote-f2b-output").textContent = data.fail2banOutput || "Fail2Ban status unavailable.";
    q<HTMLElement>("#remote-f2b-jails").textContent = data.fail2banJailCount > 0 ? String(data.fail2banJailCount) : ((data.fail2banActive === true) ? "—" : "0");
    q<HTMLElement>("#remote-f2b-banned").textContent = data.fail2banJailCount > 0 ? String(data.fail2banBanned ?? 0) : "—";
    q<HTMLElement>("#remote-auth-log").textContent = data.authLog || "No recent authentication events.";
    q<HTMLElement>("#remote-port-count").textContent = `${data.ports.length} ports`;
    q<HTMLElement>("#remote-ports-body").innerHTML = data.ports.length ? data.ports.map(p => `<tr><td>${escapeHtml(p.proto)}</td><td>${escapeHtml(p.address)}</td><td><strong>${p.port}</strong></td><td>${escapeHtml(p.process || "—")}</td></tr>`).join("") : `<tr><td colspan="4" class="empty-state">Dinleyen port bulunamadı.</td></tr>`;
    q<HTMLElement>("#remote-interfaces-body").innerHTML = data.interfaces.length ? data.interfaces.map(i => `<tr><td><strong>${escapeHtml(i.name)}</strong></td><td>${escapeHtml(i.state)}</td><td>${escapeHtml(i.ipv4 || "—")}</td><td>${escapeHtml(i.ipv6 || "—")}</td></tr>`).join("") : `<tr><td colspan="4" class="empty-state">Ağ arayüzü bulunamadı.</td></tr>`;
  } catch (error) {
    q<HTMLElement>("#remote-ssh-status").textContent = "HATA"; q<HTMLElement>("#remote-ssh-status").dataset.state = "error";
    q<HTMLElement>("#remote-auth-log").textContent = `Uzak Erişim query failed:
${String(error)}`;
  } finally { button.disabled = state.connection !== "online"; }
}

function showPage(page: string): void {
  // Dashboard does not poll in the background. A page entry performs a single
  // refresh so navigation never creates a recurring SSH session stream.
  if (page === "dashboard" && state.connection === "online") {
    void refreshDashboard();
  }

  document.querySelectorAll<HTMLElement>(".page").forEach((el) => el.classList.remove("active-page"));
  document.querySelectorAll<HTMLButtonElement>(".nav-item").forEach((el) => el.classList.remove("active"));

  const button = document.querySelector<HTMLButtonElement>(`.nav-item[data-page="${page}"]`);
  if (button) button.classList.add("active");

  const direct = document.querySelector<HTMLElement>(`#page-${page}`);
  if (direct) {
    direct.classList.add("active-page");
  } else {
    q<HTMLElement>("#placeholder-title").textContent = button?.textContent?.replace("soon", "").trim() || "Module";
    q<HTMLElement>("#page-placeholder").classList.add("active-page");
  }

  const labels: Record<string, string> = {
    dashboard: "Sunucu Paneli",
    terminal: "SSH Terminali",
    files: "Sunucu Dosyaları",
    services: "Servisler",
    updates: "Sistem Güncellemeleri",
    monitoring: "Sistem İzleme",
    logs: "Günlük Merkezi",
    remote: "Uzak Erişim",
    security: "Güvenlik Merkezi",
    settings: "Sunucu Ayarları",
  };
  q<HTMLElement>("#page-title").textContent = labels[page] || button?.textContent?.replace("Yakında", "").trim() || "Modül";

  if (page === "remote" && state.connection === "online") { void loadRemoteAccess(); }
  if (page === "security" && state.connection === "online") { void loadSecurityAudit(); }

  if (page === "services") {
    void loadServisler();
  }

  if (page === "updates" && state.connection === "online") {
    void inspectUpdates();
  }

  if (page === "monitoring") {
    if (state.connection === "online") void startMonitoring();
    else stopMonitoring();
  } else {
    stopMonitoring();
  }

  if (page === "logs") {
    if (state.connection === "online") void loadGünlükler();
    else void stopGünlüklerLive();
  } else {
    stopGünlüklerLive();
  }

  if (page === "files") {
    if (state.connection === "online") {
      currentRemotePath = currentRemotePath || `/home/${state.username}`;
      void loadFiles();
    }
  }

  if (page === "terminal") {
    ensureTerminal();
    requestAnimationFrame(() => terminal?.focus());
  }
}

q<HTMLInputElement>("#input-host").value = state.host;
q<HTMLInputElement>("#input-port").value = state.port;
q<HTMLInputElement>("#input-user").value = state.username;
q<HTMLInputElement>("#input-key").value = state.keyPath;
q<HTMLInputElement>("#input-wol-mac").value = state.wolMac;
q<HTMLInputElement>("#input-wol-broadcast").value = state.wolBroadcast;
q<HTMLInputElement>("#input-wol-port").value = state.wolPort;
setAddressText();
setConnectionStatus("offline");
setPowerButton("offline");
ensureTerminal();

q<HTMLButtonElement>("#connect-button").addEventListener("click", () => void connectTerminal());
q<HTMLButtonElement>("#refresh-button").addEventListener("click", () => void refreshDashboard());
q<HTMLButtonElement>("#system-refresh").addEventListener("click", () => void refreshDashboard());
q<HTMLButtonElement>("#power-toggle-button").addEventListener("click", () => void toggleServerPower());
q<HTMLButtonElement>("#restart-button").addEventListener("click", () => void remotePower("restart"));
q<HTMLButtonElement>("#update-button").addEventListener("click", () => void performUpdate("#update-output"));
q<HTMLButtonElement>("#update-button-page").addEventListener("click", () => void performUpdate("#update-output-page"));
q<HTMLButtonElement>("#remote-refresh-button").addEventListener("click", () => void loadRemoteAccess());
q<HTMLButtonElement>("#security-refresh-button").addEventListener("click", () => void loadSecurityAudit());
q<HTMLButtonElement>("#security-fix-close").addEventListener("click", closeSecurityFixPreview);
q<HTMLButtonElement>("#security-fix-apply-button").addEventListener("click", () => void applySecurityFix());
q<HTMLButtonElement>("#security-fix-rollback-button").addEventListener("click", () => void rollbackSecurityFix());
q<HTMLElement>("#security-fix-modal").addEventListener("click", (event) => { if (event.target === q<HTMLElement>("#security-fix-modal")) closeSecurityFixPreview(); });
q<HTMLButtonElement>("#updates-refresh-button").addEventListener("click", () => void inspectUpdates());
q<HTMLButtonElement>("#updates-history-refresh").addEventListener("click", () => void loadUpdateHistory());
q<HTMLButtonElement>("#logs-refresh-button").addEventListener("click", () => void (logsLive ? startGünlüklerLive() : loadGünlükler()));
q<HTMLButtonElement>("#logs-live-button").addEventListener("click", () => {
  const button = q<HTMLButtonElement>("#logs-live-button");
  if (button.dataset.live === "true") void stopGünlüklerLive(); else void startGünlüklerLive();
});
q<HTMLSelectElement>("#logs-service").addEventListener("change", () => { updateGünlüklerTitle(); void (logsLive ? startGünlüklerLive() : loadGünlükler()); });
q<HTMLSelectElement>("#logs-level").addEventListener("change", () => renderGünlükler());
q<HTMLSelectElement>("#logs-since").addEventListener("change", () => { if (!logsLive) void loadGünlükler(); else void loadGünlükler(); });
q<HTMLSelectElement>("#logs-lines").addEventListener("change", () => { void (logsLive ? startGünlüklerLive() : loadGünlükler()); });
q<HTMLInputElement>("#logs-search").addEventListener("input", () => renderGünlükler());

q<HTMLButtonElement>("#monitor-refresh-button").addEventListener("click", () => refreshMonitoring());
q<HTMLSelectElement>("#monitor-interval").addEventListener("change", () => { if (document.querySelector("#page-monitoring")?.classList.contains("active-page")) void startMonitoring(); });
q<HTMLButtonElement>("#terminal-button").addEventListener("click", () => showPage("terminal"));
q<HTMLButtonElement>("#terminal-close").addEventListener("click", () => void disconnectTerminal());
q<HTMLButtonElement>("#terminal-clear").addEventListener("click", () => terminal?.clear());
q<HTMLButtonElement>("#settings-button").addEventListener("click", () => showPage("settings"));
q<HTMLButtonElement>("#save-settings").addEventListener("click", () => {
  state.host = q<HTMLInputElement>("#input-host").value.trim();
  state.port = q<HTMLInputElement>("#input-port").value.trim();
  state.username = q<HTMLInputElement>("#input-user").value.trim();
  state.keyPath = q<HTMLInputElement>("#input-key").value.trim();
  state.wolMac = q<HTMLInputElement>("#input-wol-mac").value.trim();
  state.wolBroadcast = q<HTMLInputElement>("#input-wol-broadcast").value.trim();
  state.wolPort = q<HTMLInputElement>("#input-wol-port").value.trim() || "9";

  localStorage.setItem("jarvis.host", state.host);
  localStorage.setItem("jarvis.port", state.port);
  localStorage.setItem("jarvis.username", state.username);
  localStorage.setItem("jarvis.keyPath", state.keyPath);
  localStorage.setItem("jarvis.wolMac", state.wolMac);
  localStorage.setItem("jarvis.wolBroadcast", state.wolBroadcast);
  localStorage.setItem("jarvis.wolPort", state.wolPort);

  setAddressText();
  window.alert("Sunucu ayarları kaydedildi.");
});

document.querySelectorAll<HTMLButtonElement>(".nav-item").forEach((button) => {
  button.addEventListener("click", () => showPage(button.dataset.page || "dashboard"));
});


q<HTMLButtonElement>("#services-refresh-button").addEventListener("click", () => void loadServisler());
q<HTMLInputElement>("#service-search").addEventListener("input", () => renderServisler());
q<HTMLElement>("#service-filters").addEventListener("click", (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>("button[data-filter]");
  if (!button) return;
  serviceFilter = button.dataset.filter || "all";
  document.querySelectorAll<HTMLButtonElement>("#service-filters .filter-button").forEach((el) => el.classList.toggle("active", el === button));
  renderServisler();
});
q<HTMLButtonElement>("#service-log-close").addEventListener("click", () => { q<HTMLElement>("#service-log-panel").hidden = true; });
q<HTMLButtonElement>("#files-refresh-button").addEventListener("click", () => void loadFiles());
q<HTMLButtonElement>("#files-up-button").addEventListener("click", () => {
  if (currentRemotePath === `/home/${state.username}`) return;
  const idx = currentRemotePath.lastIndexOf("/");
  currentRemotePath = idx <= `/home/${state.username}`.length ? `/home/${state.username}` : currentRemotePath.slice(0, idx) || `/home/${state.username}`;
  void loadFiles();
});
q<HTMLButtonElement>("#files-upload-button").addEventListener("click", () => void uploadFile());
q<HTMLButtonElement>("#files-new-folder-button").addEventListener("click", () => void createRemoteFolder());
q<HTMLButtonElement>("#files-new-file-button").addEventListener("click", () => void createRemoteFile());
q<HTMLButtonElement>("#file-editor-close").addEventListener("click", () => q<HTMLElement>("#file-editor-modal").classList.remove("open"));
q<HTMLButtonElement>("#file-editor-cancel").addEventListener("click", () => q<HTMLElement>("#file-editor-modal").classList.remove("open"));
q<HTMLButtonElement>("#file-editor-save").addEventListener("click", () => void saveRemoteFile());
q<HTMLElement>("#file-context-menu").addEventListener("click", (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>("button[data-action]");
  if (!button || !selectedFile) return;
  const action = button.dataset.action;
  hideFileContextMenu();
  if (action === "open") {
    if (selectedFile.kind === "directory") { currentRemotePath = selectedFile.path; void loadFiles(); } else { void openRemoteFile(selectedFile); }
  } else if (action === "download") { void downloadFile(selectedFile); }
  else if (action === "rename") { void renameRemoteFile(selectedFile); }
  else if (action === "delete") { void deleteRemoteFile(selectedFile); }
  else if (action === "copy-path") { void navigator.clipboard.writeText(selectedFile.path); }
});
document.addEventListener("click", (event) => {
  if (!(event.target as HTMLElement).closest("#file-context-menu") && !(event.target as HTMLElement).closest(".row-more")) hideFileContextMenu();
});
q<HTMLElement>("#file-editor-modal").addEventListener("click", (event) => {
  if (event.target === q<HTMLElement>("#file-editor-modal")) q<HTMLElement>("#file-editor-modal").classList.remove("open");
});

window.addEventListener("beforeunload", () => {
  stopMonitoring();
  stopGünlüklerLive();
  void invoke("close_ssh").catch(() => undefined);
  unlistenOutput?.();
  unlistenClosed?.();
  unlistenMonitorOutput?.();
  unlistenMonitorHata?.();
});
