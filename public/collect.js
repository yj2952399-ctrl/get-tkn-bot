(() => {
  const token = location.pathname.split('/')[2];
  if (!token) return;

  const canvasHash = () => {
    try {
      const c = document.createElement('canvas');
      const x = c.getContext('2d');
      x.textBaseline = 'top';
      x.font = '14px Arial';
      x.fillStyle = '#f60';
      x.fillRect(0, 0, 100, 20);
      x.fillStyle = '#069';
      x.fillText('fingerprint,1', 2, 2);
      return c.toDataURL();
    } catch {
      return '';
    }
  };

  const webglInfo = () => {
    try {
      const c = document.createElement('canvas');
      const g = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!g) return '';
      const d = g.getExtension('WEBGL_debug_renderer_info');
      const vendor = d ? g.getParameter(d.UNMASKED_VENDOR_WEBGL) : g.getParameter(g.VENDOR);
      const renderer = d ? g.getParameter(d.UNMASKED_RENDERER_WEBGL) : g.getParameter(g.RENDERER);
      return `${vendor}|${renderer}|${g.getParameter(g.MAX_TEXTURE_SIZE)}`;
    } catch {
      return '';
    }
  };

  const audioHash = () => {
    try {
      const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!Ctx) return '';
      const ctx = new Ctx(1, 44100, 44100);
      const osc = ctx.createOscillator();
      osc.type = 'triangle';
      osc.frequency.value = 10000;
      const comp = ctx.createDynamicsCompressor();
      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);
      let out = '';
      ctx.oncomplete = (e) => {
        const buf = e.renderedBuffer.getChannelData(0).slice(4500, 4600);
        out = Array.from(buf).reduce((a, b) => a + Math.abs(b), 0).toFixed(6);
      };
      ctx.startRendering();
      return out;
    } catch {
      return '';
    }
  };

  const fp = {
    canvas: canvasHash().slice(-80),
    webgl: webglInfo(),
    audio: audioHash(),
    screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
    avail: `${screen.availWidth}x${screen.availHeight}`,
    dpr: devicePixelRatio,
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    offset: new Date().getTimezoneOffset(),
    lang: navigator.language,
    langs: (navigator.languages || []).join(','),
    cores: navigator.hardwareConcurrency || 0,
    mem: navigator.deviceMemory || 0,
    touch: navigator.maxTouchPoints || 0,
    platform: navigator.platform || '',
    plugins: navigator.plugins.length,
    dnt: navigator.doNotTrack || '',
    cookie: navigator.cookieEnabled,
    referrer: document.referrer,
    conn: navigator.connection ? `${navigator.connection.effectiveType}/${navigator.connection.downlink}` : ''
  };

  const send = () =>
    fetch('/api/fp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token, fp })
    }).catch(() => {});

  send();
  setTimeout(send, 800);
})();