(() => {
  const current = document.currentScript;
  if (!current) return;

  const collectUrl = current.dataset.collectUrl || "/collect/beacon";
  const startedAt = performance.now();

  const payload = {
    url: location.href,
    title: document.title,
    referrer: document.referrer,
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    lang: navigator.language,
    screen: {
      width: window.screen?.width || null,
      height: window.screen?.height || null,
      pixelRatio: window.devicePixelRatio || 1,
    },
    webdriver: Boolean(navigator.webdriver),
    headless_hint: Boolean(
      navigator.webdriver ||
      /HeadlessChrome/i.test(navigator.userAgent) ||
      !window.chrome
    ),
    dwell_ms: Math.round(performance.now() - startedAt),
    plugins_count: navigator.plugins?.length || 0,
    mime_types_count: navigator.mimeTypes?.length || 0,
    hardware_cores: navigator.hardwareConcurrency || 0,
    device_memory: navigator.deviceMemory || 0,
    max_touch_points: navigator.maxTouchPoints || 0,
    vendor: navigator.vendor || "",
    product_sub: navigator.productSub || "",
    app_version: navigator.appVersion?.substring(0, 100) || "",
  };

  const send = () => {
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
  };

  if (document.readyState === "complete") {
    send();
  } else {
    window.addEventListener("load", send, { once: true });
  }
})();
