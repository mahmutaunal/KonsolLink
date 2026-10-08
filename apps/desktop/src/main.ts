import { invoke } from '@tauri-apps/api/core';

type Status = {
  version: number;
  state: string;
  gateway: { host: string; router: string; console: string } | null;
  discord_bypass: boolean;
  intercepted_destinations: number;
  error: string | null;
};

const byId = <T extends HTMLElement>(id: string) => document.querySelector<T>(`#${id}`)!;
const toggle = byId<HTMLButtonElement>('toggle');
const ready = byId<HTMLInputElement>('ready');
const readyLabel = byId<HTMLElement>('ready-label');
const gateway = byId<HTMLElement>('gateway');
const bypass = byId<HTMLElement>('bypass');
const direct = byId<HTMLElement>('direct');
const message = byId<HTMLElement>('status');

let current: Status | null = null;
let connected = false;
let busy = false;
let polling = false;
let latchedError: string | null = null;

function setState(el: HTMLElement, kind: 'off' | 'wait' | 'good', label: string) {
  el.className = `value ${kind === 'off' ? '' : kind}`.trim();
  el.innerHTML = '<i class="dot"></i>' + label;
}

function friendlyError(raw: unknown): string {
  const detail = String(raw ?? '').trim();
  const value = detail.toLocaleLowerCase('tr-TR');
  if (value.includes('windows ağ kontrolü:')) {
    return detail;
  }
  if (value.includes('transparent discord api readiness')) {
    return `Discord API bağlantısı şeffaf yerel yoldan tamamlanamadı. Teknik ayrıntı: ${detail}`;
  }
  if (value.includes('transparent discord websocket readiness')) {
    return `Discord Gateway WebSocket bağlantısı kurulamadı. Teknik ayrıntı: ${detail}`;
  }
  if (value.includes('external dpi process') || value.includes('external zapret pf')) {
    return 'Harici Zapret/DPI hizmeti açık. Önce onu tamamen kapatıp KonsolLink’i yeniden aç.';
  }
  if (value.includes('transparent route')) {
    return `Discord’un şeffaf yerel yolu yenilenemedi. Teknik ayrıntı: ${detail}`;
  }
  if (value.includes('helper') || value.includes('socket') || value.includes('bağlantısı yok')) {
    return 'KonsolLink hizmetine ulaşılamadı. Uygulamayı yeniden aç veya yerel kurulumu onar.';
  }
  if (value.includes('internet sharing') || value.includes('forwarding')) {
    return 'Mac’te İnternet Paylaşımı veya başka bir ağ yönlendirme hizmeti açık. Kapatıp yeniden dene.';
  }
  if (value.includes('topology') || value.includes('uplink')) {
    return 'Mac’in ağ bağlantısı değişti. Wi-Fi bağlantısını kontrol edip yeniden aç.';
  }
  if (value.includes('engine process exited') || value.includes('tpws exited') || value.includes('gateway exited')) {
    return `KonsolLink ağ motoru beklenmedik şekilde durdu. Teknik ayrıntı: ${detail}`;
  }
  if (value.includes('engine child identity') || value.includes('engine process identity')) {
    return 'KonsolLink ağ motorunun çalışma durumu doğrulanamadı. Bağlantı güvenle kapatıldı.';
  }
  if (value.includes('artifact') || value.includes('hash')) {
    return 'KonsolLink ağ bileşeni doğrulanamadı. Yerel kurulumu onarmak gerekiyor.';
  }
  if (value.includes('already has an owner')) {
    return 'KonsolLink başka bir açık pencere tarafından kullanılıyor.';
  }
  return `Bağlantı güvenli biçimde durduruldu. Teknik ayrıntı: ${detail || 'Bilinmeyen hata'}`;
}

function render(status: Status) {
  current = status;
  const active = status.state === 'gateway_active' && !status.error;
  if (status.error) latchedError = status.error;
  else if (active) latchedError = null;
  setState(gateway, active ? 'good' : 'off', active ? 'Açık' : 'Hazır');
  setState(bypass, active && status.discord_bypass ? 'good' : 'off', active && status.discord_bypass ? 'Etkin' : 'Kapalı');
  setState(direct, active ? 'good' : 'off', 'Doğrudan');
  if (latchedError) {
    message.className = 'banner error';
    message.textContent = friendlyError(latchedError);
  } else if (active) {
    message.className = 'banner';
    message.textContent = 'KonsolLink açık. Konsolda yukarıdaki ağ değerlerini kullanabilirsin. Discord trafiği korumalı yerel yoldan, diğer trafik doğrudan internete çıkar.';
  } else {
    message.className = 'banner';
    message.textContent = 'Önce konsolda yukarıdaki ağ değerlerini gir. Ardından hazırlık onayını verip KonsolLink’i aç.';
  }
  controls();
}

function controls() {
  const active = current?.state === 'gateway_active';
  toggle.disabled = busy || !connected || (!active && !ready.checked);
  toggle.classList.toggle('stop', Boolean(active));
  toggle.textContent = busy ? 'İşlem tamamlanıyor…' : active ? 'KonsolLink’i kapat' : connected ? 'KonsolLink’i aç' : 'KonsolLink hazırlanıyor…';
  ready.disabled = active || busy;
}

async function request(action: 'status' | 'start' | 'stop', background = false) {
  if (busy || (background && polling)) return;
  if (!background && (action === 'start' || action === 'stop')) latchedError = null;
  if (background) polling = true;
  else { busy = true; controls(); }
  try {
    const status = await invoke<Status>('gateway_request', {
      action,
      console: '172.24.2.10',
      ipv4Only: ready.checked,
      exclusiveHost: ready.checked,
    });
    connected = true;
    render(status);
  } catch (error) {
    connected = false;
    current = null;
    latchedError = String(error ?? 'Bilinmeyen bağlantı hatası');
    setState(gateway, 'off', 'Ulaşılamıyor');
    setState(bypass, 'off', 'Kapalı');
    setState(direct, 'off', 'Doğrudan');
    message.className = 'banner error';
    message.textContent = friendlyError(latchedError);
  } finally {
    if (background) polling = false;
    else { busy = false; controls(); }
  }
}

toggle.addEventListener('click', () => void request(current?.state === 'gateway_active' ? 'stop' : 'start'));
ready.addEventListener('change', controls);

// Visibility affects only presentation refresh, never the native session.
setInterval(() => {
  if (document.visibilityState === 'visible') void request('status', true);
}, 5000);
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') void request('status', true);
});
window.addEventListener('focus', () => void request('status', true));
void request('status');
