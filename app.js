// ═══════════════════════════════════════════════════════════
//  CYBER-VAULT app.js  v2.0
//  DEK + TOTP-2FA + Yedek Kodlar + Referans Kodu + Ayarlar
// ═══════════════════════════════════════════════════════════

const firebaseConfig = {
  apiKey: "AIzaSyB61GqGjKuXya10mPjsNHF4FrRj9KsuaQ0",
  authDomain: "cyber-vault-7bb7d.firebaseapp.com",
  projectId: "cyber-vault-7bb7d",
  storageBucket: "cyber-vault-7bb7d.firebasestorage.app",
  messagingSenderId: "848534709583",
  appId: "1:848534709583:web:751faf97989a067855d13a",
  measurementId: "G-GK9JNG4VX9"
};

firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db   = firebase.firestore();

/* ── STATE ── */
let masterPassword    = '';
let DEK               = '';
let currentUser       = null;
let passwords         = [];
let filteredPasswords = [];
let _rawPasswords     = [];
let unsubSnap         = null;
let lockTimer         = null;
let lockCountdown     = 300;
let editingId         = null;
let generatedPw       = '';

// Registration temp state
let regTempData = {};

// Forgot flow
let forgotType      = '';  // 'login' | 'master'
let forgotVerified  = null;

// Codes display state
let codesVisible = { ref: false, backup: false };

// Cached user doc data
let cachedUserDoc = null;

/* ═══════════════════════════════════════════════════════════
   CRYPTO
═══════════════════════════════════════════════════════════ */
const aesEnc = (t, k) => CryptoJS.AES.encrypt(String(t||''), k).toString();
const aesDec = (c, k) => {
  try { return CryptoJS.AES.decrypt(String(c||''), k).toString(CryptoJS.enc.Utf8) || ''; }
  catch { return ''; }
};

function generateDEK() {
  const a = new Uint8Array(32);
  crypto.getRandomValues(a);
  return Array.from(a).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function hashCode(code) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code.trim().toUpperCase()));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

function generateRefCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const arr   = new Uint8Array(12);
  crypto.getRandomValues(arr);
  const raw = Array.from(arr).map(b=>chars[b%chars.length]).join('');
  return `CVT-${raw.slice(0,4)}-${raw.slice(4,8)}-${raw.slice(8,12)}`;
}

function generateBackupCodes(n=5) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from({length:n}, () => {
    const a = new Uint8Array(10);
    crypto.getRandomValues(a);
    const raw = Array.from(a).map(b=>chars[b%chars.length]).join('');
    return `${raw.slice(0,5)}-${raw.slice(5,10)}`;
  });
}

function encryptEntry(entry) {
  return {
    site:      aesEnc(entry.site,     DEK),
    username:  aesEnc(entry.username, DEK),
    email:     aesEnc(entry.email,    DEK),
    password:  aesEnc(entry.password, DEK),
    notes:     aesEnc(entry.notes||'',DEK),
    uid:       currentUser.uid,
    createdAt: entry.createdAt || firebase.firestore.FieldValue.serverTimestamp(),
    updatedAt: firebase.firestore.FieldValue.serverTimestamp()
  };
}

function decryptEntry(doc) {
  const d = doc.data ? doc.data() : doc;
  return {
    id:       doc.id,
    site:     aesDec(d.site,     DEK),
    username: aesDec(d.username, DEK),
    email:    aesDec(d.email,    DEK),
    password: aesDec(d.password, DEK),
    notes:    aesDec(d.notes,    DEK),
  };
}

/* ═══════════════════════════════════════════════════════════
   TOTP
═══════════════════════════════════════════════════════════ */

function generateTOTPSecret() {
  return new OTPAuth.Secret({ size: 20 }).base32;
}

function getTOTP(secret) {
  return new OTPAuth.TOTP({
    issuer:    'CyberVault',
    label:     currentUser?.email || 'user',
    algorithm: 'SHA1',
    digits:    6,
    period:    30,
    secret:    OTPAuth.Secret.fromBase32(secret)
  });
}

function verifyTOTP(secret, token) {
  try {
    const totp  = getTOTP(secret);
    const delta = totp.validate({ token: token.trim(), window: 1 });
    return delta !== null;
  } catch { return false; }
}

function getTOTPUri(secret, email) {
  const totp = new OTPAuth.TOTP({
    issuer:    'CyberVault',
    label:     email || 'user',
    algorithm: 'SHA1',
    digits:    6,
    period:    30,
    secret:    OTPAuth.Secret.fromBase32(secret)
  });
  return totp.toString();
}

/* ═══════════════════════════════════════════════════════════
   AUTH STATE
═══════════════════════════════════════════════════════════ */

auth.onAuthStateChanged(user => {
  if (user && masterPassword && DEK) {
    currentUser = user;
    enterDashboard();
  } else {
    showScreen('auth-screen');
  }
});

/* ═══════════════════════════════════════════════════════════
   REGISTER — Step 1: collect credentials
═══════════════════════════════════════════════════════════ */

async function registerStep1() {
  const email    = v('r-email');
  const username = v('r-username');
  const pw       = v('r-pw');
  const master   = v('r-master');
  clearErr('register-error');

  if (!email || !pw || !master) return showErr('register-error','⚠ E-posta, giriş şifresi ve ana şifre zorunludur.');
  if (pw.length < 6)     return showErr('register-error','⚠ Giriş şifresi min. 6 karakter.');
  if (master.length < 8) return showErr('register-error','⚠ Ana şifre min. 8 karakter.');

  // Generate TOTP secret and show QR
  const totpSecret = generateTOTPSecret();
  regTempData = { email, username, pw, master, totpSecret };

  const uri = getTOTPUri(totpSecret, email);
  document.getElementById('totp-secret-text').textContent = totpSecret;

  document.getElementById('reg-step1').classList.add('hidden');
  document.getElementById('reg-step2').classList.remove('hidden');

  // QR: img tag ile göster — JS kütüphanesi gerektirmez
  const qrWrap = document.getElementById('qr-img-wrap');
  const encoded = encodeURIComponent(uri);
  const size = 180;
  qrWrap.innerHTML = `<img
    src="https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encoded}&color=bc13fe&bgcolor=0a0a0c"
    width="${size}" height="${size}"
    alt="QR Code"
    style="display:block;border:2px solid rgba(188,19,254,.4);padding:8px;background:#0a0a0c"
    onerror="this.style.display='none';document.getElementById('qr-fallback').style.display='block'"
  />`;
  document.getElementById('qr-fallback').style.display = 'none';
}

/* REGISTER — Step 2: verify TOTP */
async function registerStep2() {
  const code = v('r-totp');
  clearErr('reg-totp-error');
  if (!code || code.length !== 6) return showErr('reg-totp-error','⚠ 6 haneli kodu girin.');

  if (!verifyTOTP(regTempData.totpSecret, code)) {
    return showErr('reg-totp-error','⚠ Kod yanlış veya süresi dolmuş. Tekrar deneyin.');
  }

  // Generate backup codes and reference code
  const refCode     = generateRefCode();
  const backupCodes = generateBackupCodes(5);

  regTempData.refCode     = refCode;
  regTempData.backupCodes = backupCodes;

  // Show them
  document.getElementById('display-ref-code').textContent = refCode;
  const grid = document.getElementById('backup-codes-display');
  grid.innerHTML = backupCodes.map(c => `<div class="backup-code-item">${c}</div>`).join('');

  document.getElementById('reg-step2').classList.add('hidden');
  document.getElementById('reg-step3').classList.remove('hidden');
}

/* REGISTER — Step 3: actually create account */
async function registerFinish() {
  const { email, username, pw, master, totpSecret, refCode, backupCodes } = regTempData;

  try {
    const cred = await auth.createUserWithEmailAndPassword(email, pw);
    await cred.user.updateProfile({ displayName: username || email });

    const newDEK       = generateDEK();
    const encryptedDEK = aesEnc(newDEK, master);

    // Hash kodlar (doğrulama için)
    const refHash          = await hashCode(refCode);
    const backupHashes     = await Promise.all(backupCodes.map(hashCode));

    // Düz metin şifreli sakla — Kodlar panelinde her zaman göstermek için
    const encryptedRefCode     = aesEnc(refCode, newDEK);
    const encryptedBackupCodes = backupCodes.map(c => aesEnc(c, newDEK));

    // TOTP secret'ı DEK ile şifrele
    const encryptedTOTP = aesEnc(totpSecret, newDEK);

    await db.collection('users').doc(cred.user.uid).set({
      username:             username || '',
      email,
      encryptedDEK,
      encryptedTOTP,
      totp_enabled:         true,
      admin_override:       false,
      referenceCode:        refHash,
      backupCodes:          backupHashes,
      backupCodesUsed:      [],
      encryptedRefCode,
      encryptedBackupCodes,
      dekVersion:           1,
      createdAt:            firebase.firestore.FieldValue.serverTimestamp()
    });

    masterPassword  = master;
    DEK             = newDEK;
    currentUser     = cred.user;
    cachedUserDoc   = null;

    regTempData = {};
    showToast('✓ HESAP OLUŞTURULDU — HOŞGELDİNİZ');
    enterDashboard();
  } catch(e) {
    showErr('register-error', '⚠ ' + fbErr(e.code));
    document.getElementById('reg-step3').classList.add('hidden');
    document.getElementById('reg-step1').classList.remove('hidden');
  }
}

/* ═══════════════════════════════════════════════════════════
   LOGIN — Step 1: email + pw + master
═══════════════════════════════════════════════════════════ */

/* ── Tek fonksiyon: 4 alanı birden doğrula ── */
async function handleLogin() {
  const email  = v('l-email');
  const pw     = v('l-pw');
  const master = v('l-master');
  const totp   = v('l-totp');
  clearErr('login-error');

  if (!email || !pw || !master) return showErr('login-error','⚠ E-posta, giriş şifresi ve ana şifre zorunludur.');

  try {
    const cred    = await auth.signInWithEmailAndPassword(email, pw);
    const userDoc = await db.collection('users').doc(cred.user.uid).get();

    if (!userDoc.exists) {
      await auth.signOut();
      return showErr('login-error','⚠ Kullanıcı profili bulunamadı.');
    }

    const data         = userDoc.data();
    const decryptedDEK = aesDec(data.encryptedDEK, master);

    if (!decryptedDEK || decryptedDEK.length < 32) {
      await auth.signOut();
      return showErr('login-error','⚠ Yanlış ana şifre.');
    }

    // Admin override — TOTP atla, direkt giriş
    if (data.admin_override === true) {
      // pending_pw_reset varsa (forgot login flow) Firebase Auth sifresini guncelle
      if (data.pending_pw_reset) {
        try {
          const newPw = aesDec(data.pending_pw_reset, cred.user.uid + 'temp-login-reset');
          if (newPw) await cred.user.updatePassword(newPw);
          await db.collection('users').doc(cred.user.uid).update({
            admin_override: false,
            pending_pw_reset: firebase.firestore.FieldValue.delete()
          });
        } catch(e) {
          await db.collection('users').doc(cred.user.uid).update({ admin_override: false });
        }
      } else {
        await db.collection('users').doc(cred.user.uid).update({ admin_override: false });
      }
      masterPassword = master;
      DEK            = decryptedDEK;
      currentUser    = cred.user;
      cachedUserDoc  = data;
      showToast('Giris basarili');
      enterDashboard();
      return;
    }

    // TOTP devre dışıysa direkt giriş
    if (!data.totp_enabled) {
      masterPassword = master; DEK = decryptedDEK;
      currentUser = cred.user; cachedUserDoc = data;
      enterDashboard();
      return;
    }

    // Normal akış — TOTP zorunlu
    if (!totp || totp.length !== 6) {
      await auth.signOut();
      return showErr('login-error','⚠ Authenticator kodunu girin (6 haneli).');
    }

    const totpSecret = aesDec(data.encryptedTOTP, decryptedDEK);
    if (!verifyTOTP(totpSecret, totp)) {
      await auth.signOut();
      return showErr('login-error','⚠ Authenticator kodu yanlış veya süresi dolmuş.');
    }

    masterPassword = master;
    DEK            = decryptedDEK;
    currentUser    = cred.user;
    cachedUserDoc  = data;
    showToast('✓ GİRİŞ BAŞARILI');
    enterDashboard();

  } catch(e) {
    showErr('login-error','⚠ ' + fbErr(e.code));
  }
}

/* Kayıt geri butonları */
function backToRegStep(step) {
  document.querySelectorAll('#reg-step1,#reg-step2,#reg-step3').forEach(el => el.classList.add('hidden'));
  document.getElementById('reg-step' + step).classList.remove('hidden');
}

/* ═══════════════════════════════════════════════════════════
   FORGOT PASSWORD FLOWS
═══════════════════════════════════════════════════════════ */

function showForgot(type) {
  forgotType = type;
  const titles = { login: 'GIRIS SIFRESI SIFIRLA', master: 'ANA SIFRE SIFIRLA' };
  const labels  = { login: 'YENI GIRIS SIFRESI', master: 'YENI ANA SIFRE' };
  document.getElementById('forgot-title').textContent      = titles[type];
  document.getElementById('forgot-new-label').textContent  = labels[type];
  document.getElementById('forgot-step1').classList.remove('hidden');
  document.getElementById('forgot-step2').classList.add('hidden');
  clearErr('forgot-err1'); clearErr('forgot-err2');
  document.getElementById('forgot-panel').classList.remove('hidden');
  document.getElementById('login-form').classList.add('hidden');
  document.getElementById('register-form').classList.add('hidden');
  document.querySelectorAll('.auth-tabs').forEach(t => t.style.display='none');

  // Her iki tipte de TOTP gerekli
  const totpWrap = document.getElementById('fg-totp-wrap');
  const hint     = document.getElementById('forgot-step1-hint');
  if (totpWrap) totpWrap.style.display = '';
  if (hint) hint.textContent = 'Eposta adresinizi ve authenticator kodunuzu girin.';
}

function closeForgot() {
  document.getElementById('forgot-panel').classList.add('hidden');
  document.getElementById('login-form').classList.remove('hidden');
  document.querySelectorAll('.auth-tabs').forEach(t => t.style.display='');
  forgotType = ''; forgotVerified = null;
}

async function forgotVerify() {
  const email = v('fg-email');
  const code  = v('fg-totp');
  clearErr('forgot-err1');
  if (!email) return showErr('forgot-err1','Eposta adresinizi girin.');
  if (!code || code.length !== 6) return showErr('forgot-err1','6 haneli authenticator kodunu girin.');

  try {
    // Anonim auth ile Firestore'a eris
    await auth.signInAnonymously();
    const snap = await db.collection('users').where('email','==',email).limit(1).get();
    await auth.signOut();

    if (snap.empty) return showErr('forgot-err1','Bu eposta ile kayitli hesap bulunamadi.');

    const userDoc = snap.docs[0];
    const data    = userDoc.data();
    const uid     = userDoc.id;

    // recTOTP ile dogrula (kayit sirasinda kaydedilmis recovery TOTP)
    const totpSecret = aesDec(data.recTOTP || '', uid + 'cyber-vault-recovery');
    if (!totpSecret) return showErr('forgot-err1','Kurtarma destegi bulunamadi. Admin ile iletisime gecin.');
    if (!verifyTOTP(totpSecret, code)) return showErr('forgot-err1','Authenticator kodu yanlis.');

    forgotVerified = { uid, data, email };
    document.getElementById('forgot-step1').classList.add('hidden');
    document.getElementById('forgot-step2').classList.remove('hidden');

  } catch(e) {
    showErr('forgot-err1', e.message || 'Hata olustu.');
  }
}

async function forgotSave() {
  const newPw = v('fg-newpw');
  clearErr('forgot-err2');
  if (!newPw || newPw.length < 6) return showErr('forgot-err2','⚠ Min. 6 karakter giriniz.');
  if (!forgotVerified) return showErr('forgot-err2','⚠ Önce doğrulama adımını tamamlayın.');

  try {
    if (forgotType === 'login') {
      // Yeni giris sifresini Firestore'a gecici olarak kaydet + admin_override set et
      // Kullanici bir sonraki giriste bu gecici sifre ile girecek
      const tempEncPw = aesEnc(newPw, forgotVerified.uid + 'temp-login-reset');
      await db.collection('users').doc(forgotVerified.uid).update({
        pending_pw_reset: tempEncPw,
        admin_override:   true
      });
      showToast('Giris sifreniz guncellendi. Simdi yeni sifrenizle giris yapabilirsiniz.');
      closeForgot();

    } else if (forgotType === 'master') {
      // Master password change WITHOUT knowing old master
      // We need a fresh DEK — vault data becomes inaccessible
      // But per our design, recTOTP verifies identity, so we trust this
      const newDEK       = generateDEK();
      const encryptedDEK = aesEnc(newDEK, newPw);

      await db.collection('users').doc(forgotVerified.uid).update({
        encryptedDEK,
        dekVersion: firebase.firestore.FieldValue.increment(1),
        updatedAt:  firebase.firestore.FieldValue.serverTimestamp()
      });

      // Also delete all password entries since they can't be decrypted
      const pwSnap = await db.collection('passwords').where('uid','==',forgotVerified.uid).get();
      const batch  = db.batch();
      pwSnap.docs.forEach(d => batch.delete(d.ref));
      await batch.commit();

      showToast('⚠ Ana şifre sıfırlandı. Vault içeriği temizlendi. Yeni girişle başlayabilirsiniz.');
      closeForgot();
    }
  } catch(e) {
    showErr('forgot-err2','⚠ ' + e.message);
  }
}

/* ═══════════════════════════════════════════════════════════
   DASHBOARD
═══════════════════════════════════════════════════════════ */

function enterDashboard() {
  showScreen('dashboard-screen');
  document.getElementById('sidebar-user').textContent =
    currentUser.displayName || currentUser.email?.split('@')[0] || 'USER';
  startLockTimer();
  loadPasswords();
  loadCodesPanel();
}

function showPanel(id) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  document.querySelectorAll('.nav-item[data-panel]').forEach(b =>
    b.classList.toggle('active', b.dataset.panel === id)
  );
  const titles = {
    'panel-vault':    'VAULT KAYITLARI',
    'panel-codes':    'GÜVENLİK KODLARIM',
    'panel-settings': 'AYARLAR'
  };
  document.getElementById('topbar-title').textContent = titles[id] || '';
  resetLockTimer();
  if (id === 'panel-settings') updateTotpStatusCard();
}

async function updateTotpStatusCard() {
  if (!currentUser) return;
  try {
    const snap    = await db.collection('users').doc(currentUser.uid).get();
    const enabled = snap.data()?.totp_enabled;
    const subEl   = document.getElementById('totp-status-sub');
    if (!subEl) return;
    if (enabled) {
      subEl.textContent = '2FA aktif ✓ — yeniden baglamak icin kullanin';
      subEl.style.color = '#00ff9d';
    } else {
      subEl.textContent = '⚠ 2FA kapali — hemen aktif edin!';
      subEl.style.color = '#ff2d78';
    }
  } catch {}
}

/* ═══════════════════════════════════════════════════════════
   CODES PANEL
═══════════════════════════════════════════════════════════ */

async function loadCodesPanel() {
  if (!currentUser || !DEK) return;
  try {
    const snap = await db.collection('users').doc(currentUser.uid).get();
    const data = snap.data();
    if (!data) return;

    const refEl      = document.getElementById('codes-ref-display');
    const backupList = document.getElementById('backup-codes-list');

    // Decrypt from Firestore
    const refCode     = aesDec(data.encryptedRefCode || '', DEK);
    const backupCodes = (data.encryptedBackupCodes || []).map(c => aesDec(c, DEK));

    if (refCode) {
      refEl.dataset.value = refCode;
      refEl.textContent   = codesVisible.ref ? refCode : mask(refCode);
    } else {
      refEl.textContent = '— Kod bulunamadı';
    }

    if (backupCodes.length) {
      backupList.dataset.codes = JSON.stringify(backupCodes);
      backupList.innerHTML = backupCodes.map((c, i) =>
        `<div class="backup-code-row">
          <span class="bc-num">#${i+1}</span>
          <span class="bc-val" id="bc-${i}">${codesVisible.backup ? c : mask(c)}</span>
          <button class="icon-btn" onclick="copyBackupCode('${c}')">⧉</button>
        </div>`
      ).join('');
    } else {
      backupList.innerHTML = '<p class="codes-note">Yedek kodlar bulunamadı.</p>';
    }
  } catch(e) { console.error('Codes panel error:', e); }
}

function getSessionCodes() {
  try {
    const raw = sessionStorage.getItem('cv_codes_' + currentUser?.uid);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

function saveSessionCodes(ref, backup) {
  try {
    sessionStorage.setItem('cv_codes_' + currentUser?.uid, JSON.stringify({ ref, backup }));
  } catch {}
}

function toggleCodesVisibility(type) {
  codesVisible[type] = !codesVisible[type];
  loadCodesPanel();
}

function mask(s) {
  if (!s) return '—';
  return s.replace(/[A-Z0-9]/g, '•');
}

function copyCodesRef() {
  const val = document.getElementById('codes-ref-display').dataset.value;
  if (val) { navigator.clipboard.writeText(val); showToast('⧉ Referans kodu kopyalandı'); }
}

function copyBackupCode(code) {
  navigator.clipboard.writeText(code);
  showToast('⧉ Yedek kod kopyalandı');
}

/* Override registerFinish to also save session codes */
const _origRegFinish = registerFinish;
// We'll call saveSessionCodes inside registerFinish after login

/* ═══════════════════════════════════════════════════════════
   PASSWORDS — FIRESTORE LISTENER
═══════════════════════════════════════════════════════════ */

function loadPasswords() {
  if (!currentUser || !DEK) return;
  if (unsubSnap) unsubSnap();
  unsubSnap = db.collection('passwords')
    .where('uid','==', currentUser.uid)
    .orderBy('updatedAt','desc')
    .onSnapshot(snap => {
      _rawPasswords     = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      passwords         = snap.docs.map(decryptEntry);
      filteredPasswords = [...passwords];
      renderPasswords(filteredPasswords);
      updateStats();
    }, e => console.error(e));
}

function renderPasswords(list) {
  const c = document.getElementById('password-list');
  const e = document.getElementById('empty-state');
  if (!c) return;
  if (!list || !list.length) {
    c.innerHTML = '';
    if (e) { c.appendChild(e); e.style.display='block'; }
    return;
  }
  if (e) e.style.display = 'none';
  c.innerHTML = list.map(p => `
    <div class="pw-card" id="card-${p.id}">
      <div class="pw-card-icon">${(p.site||'?')[0].toUpperCase()}</div>
      <div class="pw-card-info">
        <div class="pw-site">${esc(p.site)}</div>
        <div class="pw-meta">
          ${p.username?`<span>👤 ${esc(p.username)}</span>`:''}
          ${p.email?`<span>✉ ${esc(p.email)}</span>`:''}
        </div>
      </div>
      <div class="pw-field-wrap">
        <span class="pw-field-value" id="pv-${p.id}">••••••••••</span>
        <button class="icon-btn" onclick="toggleReveal('${p.id}')">👁</button>
        <button class="icon-btn" onclick="copyPw('${p.id}')">⧉</button>
      </div>
      <div class="pw-actions">
        <button class="icon-btn" onclick="openEditModal('${p.id}')">✎</button>
        <button class="icon-btn delete" onclick="deleteEntry('${p.id}')">✕</button>
      </div>
    </div>`).join('');
}

function updateStats() {
  document.getElementById('stat-total').textContent  = passwords.length;
  document.getElementById('stat-weak').textContent   = passwords.filter(p=>p.password&&p.password.length<10).length;
  document.getElementById('stat-strong').textContent = passwords.filter(p=>p.password&&p.password.length>=14).length;
}

function filterPasswords() {
  resetLockTimer();
  const q = document.getElementById('search-input').value.toLowerCase();
  filteredPasswords = !q ? [...passwords] : passwords.filter(p=>
    (p.site||'').toLowerCase().includes(q)||(p.username||'').toLowerCase().includes(q)||(p.email||'').toLowerCase().includes(q)
  );
  renderPasswords(filteredPasswords);
}

const revealed = new Set();
function toggleReveal(id) {
  resetLockTimer();
  const el = document.getElementById(`pv-${id}`);
  const p  = passwords.find(x=>x.id===id);
  if (!p||!el) return;
  if (revealed.has(id)) { revealed.delete(id); el.textContent='••••••••••'; el.style.color=''; }
  else { revealed.add(id); el.textContent=p.password; el.style.color='var(--neon-green)'; }
}

function copyPw(id) {
  resetLockTimer();
  const p = passwords.find(x=>x.id===id);
  if (p) navigator.clipboard.writeText(p.password).then(()=>showToast('⧉ Şifre kopyalandı'));
}

/* ═══════════════════════════════════════════════════════════
   MODAL — ADD / EDIT
═══════════════════════════════════════════════════════════ */

function openAddModal() {
  resetLockTimer(); editingId=null;
  document.getElementById('modal-title').textContent='YENİ KAYIT EKLE';
  ['entry-site','entry-username','entry-email','entry-password','entry-notes'].forEach(id=>{
    const el=document.getElementById(id); if(el) el.value='';
  });
  document.getElementById('save-btn').querySelector('.btn-text').textContent='KAYDET';
  document.getElementById('modal-overlay').classList.remove('hidden');
  document.getElementById('generator-panel').classList.add('hidden');
  clearErr('modal-error');
}

function openEditModal(id) {
  resetLockTimer();
  const p = passwords.find(x=>x.id===id); if(!p) return;
  editingId=id;
  document.getElementById('modal-title').textContent='KAYDI DÜZENLE';
  document.getElementById('entry-site').value     = p.site||'';
  document.getElementById('entry-username').value = p.username||'';
  document.getElementById('entry-email').value    = p.email||'';
  document.getElementById('entry-password').value = p.password||'';
  document.getElementById('entry-notes').value    = p.notes||'';
  document.getElementById('save-btn').querySelector('.btn-text').textContent='GÜNCELLE';
  document.getElementById('modal-overlay').classList.remove('hidden');
  clearErr('modal-error');
}

function closeModal(e) { if(e.target.id==='modal-overlay') closeModalDirect(); }
function closeModalDirect() { document.getElementById('modal-overlay').classList.add('hidden'); }

async function saveEntry() {
  resetLockTimer();
  const site=v('entry-site'), pw=v('entry-password');
  clearErr('modal-error');
  if(!site||!pw) return showErr('modal-error','⚠ Site adı ve şifre zorunludur.');
  const enc = encryptEntry({
    site, pw,
    username: document.getElementById('entry-username').value.trim(),
    email:    document.getElementById('entry-email').value.trim(),
    password: pw,
    notes:    document.getElementById('entry-notes').value.trim()
  });
  try {
    document.getElementById('save-btn').querySelector('.btn-text').textContent='KAYDEDİLİYOR...';
    if (editingId) { await db.collection('passwords').doc(editingId).update(enc); showToast('✓ Güncellendi'); }
    else           { await db.collection('passwords').add(enc); showToast('✓ Eklendi'); }
    closeModalDirect();
  } catch(e) {
    showErr('modal-error','⚠ '+e.message);
    document.getElementById('save-btn').querySelector('.btn-text').textContent=editingId?'GÜNCELLE':'KAYDET';
  }
}

async function deleteEntry(id) {
  resetLockTimer();
  if(!confirm('Bu kaydı silmek istiyor musunuz?')) return;
  await db.collection('passwords').doc(id).delete();
  showToast('✓ Silindi');
}

/* ═══════════════════════════════════════════════════════════
   GENERATOR
═══════════════════════════════════════════════════════════ */

function toggleGenerator() {
  const p=document.getElementById('generator-panel');
  p.classList.toggle('hidden');
  if(!p.classList.contains('hidden')) generatePassword();
}

function generatePassword() {
  const len=parseInt(document.getElementById('gen-length').value);
  let cs='';
  if(document.getElementById('gen-upper').checked)   cs+='ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if(document.getElementById('gen-lower').checked)   cs+='abcdefghijklmnopqrstuvwxyz';
  if(document.getElementById('gen-nums').checked)    cs+='0123456789';
  if(document.getElementById('gen-symbols').checked) cs+='!@#$%^&*()-_=+[]{}|;:,.<>?';
  if(!cs) cs='abcdefghijklmnopqrstuvwxyz';
  const a=new Uint32Array(len); crypto.getRandomValues(a);
  generatedPw=Array.from(a).map(n=>cs[n%cs.length]).join('');
  document.getElementById('gen-preview').textContent=generatedPw;
}

function useGeneratedPassword() {
  if(!generatedPw) return;
  document.getElementById('entry-password').value=generatedPw;
  document.getElementById('generator-panel').classList.add('hidden');
  showToast('✓ Şifre alanı güncellendi');
}

/* ═══════════════════════════════════════════════════════════
   SETTINGS MODAL
═══════════════════════════════════════════════════════════ */

const settingsTitles = {
  email:   'E-POSTA DEĞİŞTİR',
  loginpw: 'GİRİŞ ŞİFRESİ DEĞİŞTİR',
  master:  'ANA ŞİFRE DEĞİŞTİR',
  delete:  'HESABI SİL'
};

const settingsHTML = {
  email: `
    <div class="input-group"><label>MEVCUT GİRİŞ ŞİFRESİ</label>
      <div class="input-wrap"><span class="input-icon">🔑</span>
        <input type="password" id="s-loginpw" placeholder="Doğrulama için giriş şifreniz"/>
        <button class="toggle-pw" onclick="togglePw('s-loginpw',this)">👁</button>
      </div></div>
    <div class="input-group"><label>YENİ E-POSTA</label>
      <div class="input-wrap"><span class="input-icon">✉</span>
        <input type="email" id="s-newemail" placeholder="yeni@mail.com"/>
      </div></div>
    <div class="modal-footer"><button class="btn-cyber btn-ghost" onclick="closeSettingsModalDirect()">İPTAL</button>
      <button class="btn-cyber btn-primary" onclick="settingsSave('email')"><span class="btn-text">GÜNCELLE</span></button></div>`,

  loginpw: `
    <div class="input-group"><label>MEVCUT GİRİŞ ŞİFRESİ</label>
      <div class="input-wrap"><span class="input-icon">🔑</span>
        <input type="password" id="s-curpw" placeholder="Mevcut giriş şifreniz"/>
        <button class="toggle-pw" onclick="togglePw('s-curpw',this)">👁</button>
      </div></div>
    <div class="input-group"><label>YENİ GİRİŞ ŞİFRESİ</label>
      <div class="input-wrap"><span class="input-icon">🔑</span>
        <input type="password" id="s-newpw" placeholder="Yeni giriş şifresi (min. 6)"/>
        <button class="toggle-pw" onclick="togglePw('s-newpw',this)">👁</button>
      </div></div>
    <div class="modal-footer"><button class="btn-cyber btn-ghost" onclick="closeSettingsModalDirect()">İPTAL</button>
      <button class="btn-cyber btn-primary" onclick="settingsSave('loginpw')"><span class="btn-text">GÜNCELLE</span></button></div>`,

  master: `
    <p class="field-hint" style="margin-bottom:12px">DEK yeni ana şifreyle yeniden şifrelenir. Vault verileriniz korunur ✓</p>
    <div class="input-group"><label>MEVCUT ANA ŞİFRE</label>
      <div class="input-wrap"><span class="input-icon">🔐</span>
        <input type="password" id="s-curmaster" placeholder="Mevcut ana şifreniz"/>
        <button class="toggle-pw" onclick="togglePw('s-curmaster',this)">👁</button>
      </div></div>
    <div class="input-group"><label>YENİ ANA ŞİFRE</label>
      <div class="input-wrap"><span class="input-icon">🔐</span>
        <input type="password" id="s-newmaster" placeholder="Yeni ana şifre (min. 8)"/>
        <button class="toggle-pw" onclick="togglePw('s-newmaster',this)">👁</button>
      </div></div>
    <div class="input-group"><label>YENİ ANA ŞİFRE (TEKRAR)</label>
      <div class="input-wrap"><span class="input-icon">🔐</span>
        <input type="password" id="s-newmaster2" placeholder="Tekrar girin"/>
        <button class="toggle-pw" onclick="togglePw('s-newmaster2',this)">👁</button>
      </div></div>
    <div class="modal-footer"><button class="btn-cyber btn-ghost" onclick="closeSettingsModalDirect()">İPTAL</button>
      <button class="btn-cyber btn-primary" onclick="settingsSave('master')"><span class="btn-text">GÜNCELLE</span></button></div>`,

  delete: `
    <div class="warning-box" style="margin-bottom:16px">
      <p class="warn-title">⚠ GERİ ALINAMAZ</p>
      <p class="warn-text">Tüm vault verileriniz ve hesabınız kalıcı olarak silinir. Aynı e-posta ile yeniden kayıt olabilirsiniz.</p>
    </div>
    <div class="input-group"><label>E-POSTA</label>
      <div class="input-wrap"><span class="input-icon">◈</span>
        <input type="email" id="s-del-email" placeholder="Hesap e-postanız"/>
      </div></div>
    <div class="input-group"><label>GİRİŞ ŞİFRESİ</label>
      <div class="input-wrap"><span class="input-icon">🔑</span>
        <input type="password" id="s-del-pw" placeholder="Giriş şifreniz"/>
        <button class="toggle-pw" onclick="togglePw('s-del-pw',this)">👁</button>
      </div></div>
    <div class="input-group"><label>ANA ŞİFRE</label>
      <div class="input-wrap"><span class="input-icon">🔐</span>
        <input type="password" id="s-del-master" placeholder="Ana şifreniz"/>
        <button class="toggle-pw" onclick="togglePw('s-del-master',this)">👁</button>
      </div></div>
    <div class="modal-footer"><button class="btn-cyber btn-ghost" onclick="closeSettingsModalDirect()">İPTAL</button>
      <button class="btn-cyber btn-primary btn-danger" onclick="settingsSave('delete')"><span class="btn-text">HESABI SİL</span></button></div>`
};


/* ═══════════════════════════════════════════════════
   2FA YENİDEN KURULUM
═══════════════════════════════════════════════════ */

let totpSetupSecret = '';

function openTotpSetupModal() {
  totpSetupSecret = '';
  document.getElementById('totp-setup-modal').classList.remove('hidden');
  document.getElementById('totp-modal-step1').classList.remove('hidden');
  document.getElementById('totp-modal-step2').classList.add('hidden');
  document.getElementById('totp-modal-step3').classList.add('hidden');
  document.getElementById('totp-verify-master').value = '';
  document.getElementById('totp-modal-code').value = '';
  clearErr('totp-modal-err1');
  clearErr('totp-modal-err2');
}

function closeTotpModal(e) {
  if (e && e.target !== document.getElementById('totp-setup-modal')) return;
  document.getElementById('totp-setup-modal').classList.add('hidden');
}

async function totpSetupStep1() {
  const master = document.getElementById('totp-verify-master').value;
  clearErr('totp-modal-err1');
  if (!master) return showErr('totp-modal-err1', '⚠ Ana şifrenizi girin.');

  // Verify master password via DEK
  try {
    const snap = await db.collection('users').doc(currentUser.uid).get();
    const testDEK = aesDec(snap.data().encryptedDEK, master);
    if (!testDEK || testDEK.length < 32) return showErr('totp-modal-err1', '⚠ Yanlış ana şifre.');
  } catch {
    return showErr('totp-modal-err1', '⚠ Doğrulama hatası.');
  }

  // Generate new TOTP secret
  totpSetupSecret = new OTPAuth.Secret({ size: 20 }).base32;
  const totp = new OTPAuth.TOTP({
    issuer: 'CyberVault',
    label: currentUser.email,
    algorithm: 'SHA1', digits: 6, period: 30,
    secret: OTPAuth.Secret.fromBase32(totpSetupSecret)
  });
  const uri = totp.toString();

  // Show QR
  const qrWrap = document.getElementById('totp-modal-qr');
  const encoded = encodeURIComponent(uri);
  qrWrap.innerHTML = `<img src="https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=${encoded}&color=bc13fe&bgcolor=0a0a0c" width="160" height="160"
    onerror="this.style.display='none'" alt="QR"/>`;
  document.getElementById('totp-modal-secret').textContent = totpSetupSecret;

  document.getElementById('totp-modal-step1').classList.add('hidden');
  document.getElementById('totp-modal-step2').classList.remove('hidden');
}

async function totpSetupStep2() {
  const code = document.getElementById('totp-modal-code').value.trim();
  clearErr('totp-modal-err2');
  if (!code || code.length !== 6) return showErr('totp-modal-err2', '⚠ 6 haneli kodu girin.');

  // Verify code
  const totp = new OTPAuth.TOTP({
    issuer: 'CyberVault', label: currentUser.email,
    algorithm: 'SHA1', digits: 6, period: 30,
    secret: OTPAuth.Secret.fromBase32(totpSetupSecret)
  });
  if (totp.validate({ token: code, window: 1 }) === null) {
    return showErr('totp-modal-err2', '⚠ Kod yanlış veya süresi dolmuş. Tekrar deneyin.');
  }

  // Save new encrypted TOTP to Firestore
  try {
    const newEncryptedTOTP = aesEnc(totpSetupSecret, DEK);
    await db.collection('users').doc(currentUser.uid).update({
      encryptedTOTP: newEncryptedTOTP,
      totp_enabled:  true
    });

    // Update totp status text
    const subEl = document.getElementById('totp-status-sub');
    if (subEl) subEl.textContent = '2FA aktif — yeniden bağlamak için kullanın';

    document.getElementById('totp-modal-step2').classList.add('hidden');
    document.getElementById('totp-modal-step3').classList.remove('hidden');
    showToast('✓ 2FA başarıyla aktif edildi');
  } catch(e) {
    showErr('totp-modal-err2', '⚠ Kayıt hatası: ' + e.message);
  }
}

function openSettingsModal(type) {
  resetLockTimer();
  if (type === 'totp') { openTotpSetupModal(); return; }
  document.getElementById('settings-modal-title').textContent = settingsTitles[type];
  document.getElementById('settings-modal-body').innerHTML    = settingsHTML[type];
  document.getElementById('settings-modal-overlay').classList.remove('hidden');
  clearErr('settings-modal-error');
}

function closeSettingsModal(e) { if(e.target.id==='settings-modal-overlay') closeSettingsModalDirect(); }
function closeSettingsModalDirect() { document.getElementById('settings-modal-overlay').classList.add('hidden'); }

async function settingsSave(type) {
  clearErr('settings-modal-error');
  try {
    if (type === 'email') {
      const loginPw  = document.getElementById('s-loginpw').value;
      const newEmail = document.getElementById('s-newemail').value.trim();
      if (!loginPw || !newEmail) return showErr('settings-modal-error','⚠ Tüm alanları doldurun.');
      const cred = firebase.auth.EmailAuthProvider.credential(currentUser.email, loginPw);
      await currentUser.reauthenticateWithCredential(cred);
      await currentUser.updateEmail(newEmail);
      await db.collection('users').doc(currentUser.uid).update({ email: newEmail });
      showToast('✓ E-posta güncellendi'); closeSettingsModalDirect();

    } else if (type === 'loginpw') {
      const curPw = document.getElementById('s-curpw').value;
      const newPw = document.getElementById('s-newpw').value;
      if (!curPw || !newPw) return showErr('settings-modal-error','⚠ Tüm alanları doldurun.');
      if (newPw.length < 6) return showErr('settings-modal-error','⚠ Min. 6 karakter.');
      const cred = firebase.auth.EmailAuthProvider.credential(currentUser.email, curPw);
      await currentUser.reauthenticateWithCredential(cred);
      await currentUser.updatePassword(newPw);
      showToast('✓ Giriş şifresi güncellendi'); closeSettingsModalDirect();

    } else if (type === 'master') {
      const curM  = document.getElementById('s-curmaster').value;
      const newM  = document.getElementById('s-newmaster').value;
      const newM2 = document.getElementById('s-newmaster2').value;
      if (!curM||!newM||!newM2) return showErr('settings-modal-error','⚠ Tüm alanları doldurun.');
      if (newM.length < 8) return showErr('settings-modal-error','⚠ Ana şifre min. 8 karakter.');
      if (newM !== newM2)  return showErr('settings-modal-error','⚠ Şifreler eşleşmiyor.');

      // Verify old master by decrypting DEK
      const userDoc = await db.collection('users').doc(currentUser.uid).get();
      const testDEK = aesDec(userDoc.data().encryptedDEK, curM);
      if (!testDEK || testDEK.length < 32) return showErr('settings-modal-error','⚠ Mevcut ana şifre yanlış.');

      const newEncDEK = aesEnc(testDEK, newM);
      await db.collection('users').doc(currentUser.uid).update({
        encryptedDEK: newEncDEK,
        dekVersion:   firebase.firestore.FieldValue.increment(1)
      });
      masterPassword = newM;
      showToast('✓ Ana şifre güncellendi — Vault korundu'); closeSettingsModalDirect();

    } else if (type === 'delete') {
      const email  = document.getElementById('s-del-email').value.trim();
      const pw     = document.getElementById('s-del-pw').value;
      const master = document.getElementById('s-del-master').value;
      if (!email||!pw||!master) return showErr('settings-modal-error','⚠ Tüm alanları doldurun.');

      // Re-auth
      const cred = firebase.auth.EmailAuthProvider.credential(email, pw);
      await currentUser.reauthenticateWithCredential(cred);

      // Verify master
      const userDoc = await db.collection('users').doc(currentUser.uid).get();
      const testDEK = aesDec(userDoc.data().encryptedDEK, master);
      if (!testDEK||testDEK.length<32) return showErr('settings-modal-error','⚠ Ana şifre yanlış.');

      // Delete all passwords
      const pwSnap = await db.collection('passwords').where('uid','==',currentUser.uid).get();
      const batch  = db.batch();
      pwSnap.docs.forEach(d => batch.delete(d.ref));
      batch.delete(db.collection('users').doc(currentUser.uid));
      await batch.commit();

      // Delete Firebase Auth account
      await currentUser.delete();
      showToast('✓ Hesap silindi'); await handleLogout();
    }
  } catch(e) {
    showErr('settings-modal-error','⚠ ' + (e.message || fbErr(e.code)));
  }
}

/* ═══════════════════════════════════════════════════════════
   AUTO-LOCK
═══════════════════════════════════════════════════════════ */

function startLockTimer() {
  stopLockTimer(); lockCountdown=300; updateTimerDisplay();
  lockTimer=setInterval(()=>{ lockCountdown--; updateTimerDisplay(); if(lockCountdown<=0) lockVault(); },1000);
  ['mousemove','keydown','click','touchstart'].forEach(ev=>document.addEventListener(ev,resetLockTimer,{passive:true}));
}

function resetLockTimer() { lockCountdown=300; updateTimerDisplay(); }

function stopLockTimer() {
  if(lockTimer){clearInterval(lockTimer);lockTimer=null;}
  ['mousemove','keydown','click','touchstart'].forEach(ev=>document.removeEventListener(ev,resetLockTimer));
}

function updateTimerDisplay() {
  const m=Math.floor(lockCountdown/60), s=String(lockCountdown%60).padStart(2,'0');
  const el=document.getElementById('timer-display');
  if(el){el.textContent=`${m}:${s}`;el.style.color=lockCountdown<=60?'var(--neon-pink)':'var(--neon-green)';}
}

function lockVault() {
  stopLockTimer();
  showScreen('lock-screen');
  showToast('🔒 Vault kilitlendi');
}

async function unlockVault() {
  const master = document.getElementById('unlock-master').value;
  const code   = document.getElementById('unlock-totp').value;
  clearErr('unlock-error');
  if(!master) return showErr('unlock-error','⚠ Ana şifrenizi girin.');
  if(!code||code.length!==6) return showErr('unlock-error','⚠ Authenticator kodunu girin.');

  try {
    const userDoc  = await db.collection('users').doc(currentUser.uid).get();
    const data     = userDoc.data();
    const testDEK  = aesDec(data.encryptedDEK, master);
    if(!testDEK||testDEK.length<32) return showErr('unlock-error','⚠ Yanlış ana şifre.');

    const totpSec  = aesDec(data.encryptedTOTP, testDEK);
    if(!verifyTOTP(totpSec, code)) return showErr('unlock-error','⚠ Authenticator kodu yanlış.');

    masterPassword = master; DEK = testDEK;
    document.getElementById('unlock-master').value='';
    document.getElementById('unlock-totp').value='';

    passwords = _rawPasswords.map(raw => ({
      id: raw.id,
      site:     aesDec(raw.site,     DEK),
      username: aesDec(raw.username, DEK),
      email:    aesDec(raw.email,    DEK),
      password: aesDec(raw.password, DEK),
      notes:    aesDec(raw.notes,    DEK),
    }));
    filteredPasswords=[...passwords];

    showScreen('dashboard-screen');
    startLockTimer();
    renderPasswords(filteredPasswords);
    updateStats();
    showToast('🔓 Vault açıldı');
  } catch(e) { showErr('unlock-error','⚠ '+e.message); }
}

/* ═══════════════════════════════════════════════════════════
   LOGOUT
═══════════════════════════════════════════════════════════ */

async function handleLogout() {
  stopLockTimer();
  masterPassword=''; DEK=''; currentUser=null; passwords=[]; _rawPasswords=[]; cachedUserDoc=null;
  if(unsubSnap){unsubSnap();unsubSnap=null;}
  await auth.signOut();
  showScreen('auth-screen');
  // Reset reg form
  document.querySelectorAll('#reg-step1,#reg-step2,#reg-step3').forEach(el => el.classList.add('hidden'));
  document.getElementById('reg-step1').classList.remove('hidden');
}

/* ═══════════════════════════════════════════════════════════
   STRENGTH METER
═══════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded',()=>{
  document.getElementById('r-master')?.addEventListener('input',e=>updateStrength(e.target.value));
});

function updateStrength(pw) {
  let s=0;
  if(pw.length>=8)s++;if(pw.length>=14)s++;
  if(/[A-Z]/.test(pw))s++;if(/[0-9]/.test(pw))s++;if(/[^A-Za-z0-9]/.test(pw))s++;
  const f=document.getElementById('strength-fill'),l=document.getElementById('strength-label');
  if(!f||!l)return;
  f.style.width=(s/5*100)+'%';
  const c=['var(--neon-pink)','var(--neon-pink)','#f5a623','var(--neon-blue)','var(--neon-green)'];
  const t=['ÇOK ZAYIF','ZAYIF','ORTA','GÜÇLÜ','ÇOK GÜÇLÜ'];
  f.style.background=c[Math.min(s,4)];l.textContent=t[Math.min(s,4)];l.style.color=c[Math.min(s,4)];
}

/* ═══════════════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════════════════ */

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s=>s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

function showToast(msg,dur=2800) {
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.remove('hidden');
  setTimeout(()=>t.classList.add('hidden'),dur);
}

function showErr(id,msg){const e=document.getElementById(id);if(e){e.textContent=msg;e.classList.remove('hidden');}}
function clearErr(id){const e=document.getElementById(id);if(e){e.textContent='';e.classList.add('hidden');}}

function togglePw(id,btn) {
  const el=document.getElementById(id); if(!el)return;
  el.type=el.type==='password'?'text':'password';
  btn.textContent=el.type==='password'?'👁':'🙈';
}

function switchAuthTab(tab) {
  document.querySelectorAll('.tab-btn').forEach((b,i)=>
    b.classList.toggle('active',(i===0&&tab==='login')||(i===1&&tab==='register'))
  );
  document.getElementById('login-form').classList.toggle('active',tab==='login');
  document.getElementById('register-form').classList.toggle('active',tab==='register');
  document.getElementById('forgot-panel').classList.add('hidden');
}

const v   = id => document.getElementById(id)?.value.trim()||'';
const esc = s  => (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

function copySecret() {
  const t=document.getElementById('totp-secret-text').textContent;
  navigator.clipboard.writeText(t).then(()=>showToast('⧉ TOTP gizli anahtar kopyalandı'));
}

function copyRefCode() {
  const t=document.getElementById('display-ref-code').textContent;
  navigator.clipboard.writeText(t).then(()=>showToast('⧉ Referans kodu kopyalandı'));
}

function fbErr(code) {
  const m={
    'auth/email-already-in-use':'Bu e-posta zaten kullanımda.',
    'auth/weak-password':'Şifre çok zayıf.',
    'auth/user-not-found':'Kullanıcı bulunamadı.',
    'auth/wrong-password':'Yanlış şifre.',
    'auth/invalid-email':'Geçersiz e-posta.',
    'auth/too-many-requests':'Çok fazla deneme. Bekleyin.',
    'auth/invalid-credential':'Geçersiz kimlik bilgileri.',
    'auth/requires-recent-login':'Yeniden giriş gerekli.',
  };
  return m[code]||code||'Bilinmeyen hata.';
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){
    if(!document.getElementById('modal-overlay').classList.contains('hidden')) closeModalDirect();
    if(!document.getElementById('settings-modal-overlay').classList.contains('hidden')) closeSettingsModalDirect();
  }
  if(e.key==='Enter'&&document.getElementById('lock-screen').classList.contains('active')) unlockVault();
});

// Save session codes after registration finishes
const origRegFinishRef = registerFinish;
// Patch registerFinish to save session codes
window.addEventListener('load', () => {
  const origFn = window.registerFinish;
  window.registerFinish = async function() {
    const { refCode, backupCodes } = regTempData;
    await origFn.call(this);
    if (currentUser && refCode && backupCodes) {
      saveSessionCodes(refCode, backupCodes);
    }
  };
});
