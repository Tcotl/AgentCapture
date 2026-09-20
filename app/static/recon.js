(() => {
  const script = document.currentScript;
  if (!script) return;

  const collectUrl = script.dataset.collectUrl || "/recon/fingerprint";

  const payload = {
    url: location.href,
    session_id: document.cookie.match(/ach_sid=([^;]+)/)?.[1] || "",
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language,
    platform: navigator.platform,
    cores: navigator.hardwareConcurrency || 0,
    memory_gb: navigator.deviceMemory || 0,
    screen_width: window.screen?.width || 0,
    screen_height: window.screen?.height || 0,
    pixel_ratio: window.devicePixelRatio || 1,
    touch_points: navigator.maxTouchPoints || 0,
    webdriver: Boolean(navigator.webdriver),
    headless_hint: Boolean(
      navigator.webdriver ||
      /HeadlessChrome/i.test(navigator.userAgent) ||
      !window.chrome
    ),
    plugins: [],
    fonts: [],
    webrtc_ips: [],
    canvas_hash: "",
    webgl_vendor: "",
    webgl_renderer: "",
  };

  function collectPlugins() {
    const plugins = [];
    for (let i = 0; i < navigator.plugins.length; i++) {
      const p = navigator.plugins[i];
      if (p && p.name) plugins.push(p.name);
    }
    return plugins.slice(0, 50);
  }

  function collectFonts() {
    const baseFonts = ["monospace", "sans-serif", "serif"];
    const testFonts = [
      "Arial", "Verdana", "Times New Roman", "Courier New",
      "Comic Sans MS", "Impact", "Georgia", "Trebuchet MS",
      "Helvetica", "Lucida Console", "Tahoma", "Consolas",
      "Segoe UI", "Roboto", "Open Sans", "Ubuntu",
      "PT Sans", "Source Code Pro", "Fira Code", "JetBrains Mono",
      "Cascadia Code", "Menlo", "Monaco",
      "SimSun", "Microsoft YaHei", "PingFang SC", "Hiragino Sans GB",
      "Noto Sans CJK SC", "WenQuanYi Micro Hei",
      "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji",
    ];
    const detected = [];
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (!ctx) return detected;
    const testString = "mmmmmmmmmmlli";
    const testSize = "72px";
    for (const baseFont of baseFonts) {
      canvas.width = 200;
      canvas.height = 80;
      ctx.font = `${testSize} ${baseFont}`;
      const baseWidth = ctx.measureText(testString).width;
      for (const font of testFonts) {
        ctx.font = `${testSize} '${font}', ${baseFont}`;
        const width = ctx.measureText(testString).width;
        if (width !== baseWidth) {
          detected.push(font);
        }
      }
    }
    return [...new Set(detected)];
  }

  function collectCanvasDataURL() {
    try {
      const canvas = document.createElement("canvas");
      canvas.width = 280;
      canvas.height = 60;
      const ctx = canvas.getContext("2d");
      if (!ctx) return "";
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.fillStyle = "#f60";
      ctx.fillRect(10, 5, 30, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("Browser Fingerprint ◈", 5, 35);
      ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
      ctx.beginPath();
      ctx.arc(80, 20, 10, 0, Math.PI * 2, true);
      ctx.fill();
      return canvas.toDataURL();
    } catch (_) {
      return "";
    }
  }

  function fnv1a64(str) {
    // Two-lane FNV-1a: deterministic fallback when SubtleCrypto is
    // unavailable (e.g. insecure origins without crypto.subtle).
    var h1 = 0x811c9dc5, h2 = 0xc2b2ae35;
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ c, 16777619) >>> 0;
      h2 = Math.imul(h2 ^ c, 2246822519) >>> 0;
    }
    return ("0000000" + h1.toString(16)).slice(-8) + ("0000000" + h2.toString(16)).slice(-8);
  }

  async function digestHex(str) {
    if (str && window.crypto && crypto.subtle && crypto.subtle.digest) {
      try {
        const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
        const bytes = new Uint8Array(buf);
        let hex = "";
        for (let i = 0; i < bytes.length; i++) hex += ("0" + bytes[i].toString(16)).slice(-2);
        return hex;
      } catch (_) {}
    }
    return str ? fnv1a64(str) : "";
  }

  function collectWebGL() {
    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) return { vendor: "", renderer: "" };
      const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
      return {
        vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : "",
        renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : "",
      };
    } catch (_) {
      return { vendor: "", renderer: "" };
    }
  }

  function isValidIP(value) {
    if (!value) return false;
    // IPv4
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return true;
    // IPv6 (hex groups + colons, optional zone id like %en0)
    return value.indexOf(":") !== -1 && /^[0-9a-fA-F:.]+(%[0-9a-zA-Z]+)?$/.test(value);
  }

  function collectWebRTCIPs(callback) {
    const ips = [];
    let done = false;
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
    });
    pc.createDataChannel("");
    pc.onicecandidate = (e) => {
      if (!e.candidate) {
        if (!done) {
          done = true;
          callback(ips);
        }
        pc.close();
        return;
      }
      // Modern Chrome/Safari obfuscate host candidates behind mDNS
      // hostnames (uuid.local); only keep real IPv4/IPv6 addresses.
      const addr = e.candidate.address || "";
      const candidate = e.candidate.candidate || "";
      if (isValidIP(addr)) {
        if (ips.indexOf(addr) === -1) ips.push(addr);
        return;
      }
      const tokens = candidate.split(/\s+/);
      for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i];
        if (isValidIP(tok) && ips.indexOf(tok) === -1) ips.push(tok);
      }
    };
    pc.createOffer().then((offer) => pc.setLocalDescription(offer)).catch(() => {});
    setTimeout(() => {
      if (!done) {
        done = true;
        callback(ips);
        pc.close();
      }
    }, 3000);
  }

  async function send(webrtcIPs) {
    payload.plugins = collectPlugins();
    payload.fonts = collectFonts();
    payload.canvas_hash = await digestHex(collectCanvasDataURL());
    const gl = collectWebGL();
    payload.webgl_vendor = gl.vendor;
    payload.webgl_renderer = gl.renderer;
    payload.webrtc_ips = webrtcIPs || [];

    const body = JSON.stringify(payload);

    try {
      if (navigator.sendBeacon) {
        const blob = new Blob([body], { type: "application/json" });
        navigator.sendBeacon(collectUrl, blob);
        return;
      }
    } catch (_) {}

    fetch(collectUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      credentials: "same-origin",
      keepalive: true,
    }).catch(() => {});
  }

  if (document.readyState === "complete") {
    collectWebRTCIPs(send);
  } else {
    window.addEventListener("load", () => collectWebRTCIPs(send), { once: true });
  }
})();
