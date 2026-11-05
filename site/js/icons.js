/* Set de íconos vectoriales (estilo línea, tipo Lucide). Sin dependencias.
   Uso: UPSEC.icon('image')  ->  string SVG.  Estilo vía CSS (.i). */
(function () {
  window.UPSEC = window.UPSEC || { tools: [] };

  var P = {
    img: ['<rect x="3" y="3" width="18" height="18" rx="2"/>', '<circle cx="8.5" cy="8.5" r="1.8"/>', '<path d="m21 15-4.5-4.5a2 2 0 0 0-2.8 0L4 20"/>'],
    eye: ['<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/>', '<circle cx="12" cy="12" r="3"/>'],
    fingerprint: ['<path d="M12 4.5a7.5 7.5 0 0 0-7.5 7.5v2"/>', '<path d="M12 8a4 4 0 0 0-4 4v4"/>', '<path d="M12 11.5v5"/>', '<path d="M16 12a4 4 0 0 0-1.2-2.8"/>', '<path d="M19.5 14v-2A7.5 7.5 0 0 0 15 5.2"/>', '<path d="M8 19.5A6 6 0 0 0 11 20"/>'],
    monitor: ['<rect x="2.5" y="4" width="19" height="13" rx="2"/>', '<path d="M8.5 21h7M12 17v4"/>'],
    cpu: ['<rect x="5" y="5" width="14" height="14" rx="2.5"/>', '<rect x="9" y="9" width="6" height="6" rx="1"/>', '<path d="M9 2.5v2.5M15 2.5v2.5M9 19v2.5M15 19v2.5M2.5 9H5M2.5 15H5M19 9h2.5M19 15h2.5"/>'],
    clock: ['<circle cx="12" cy="12" r="9.5"/>', '<path d="M12 7v5l3.5 2"/>'],
    wifi: ['<path d="M5 12.5a10 10 0 0 1 14 0"/>', '<path d="M8 15.5a6 6 0 0 1 8 0"/>', '<path d="M11 18.5a2 2 0 0 1 2 0"/>'],
    globe: ['<circle cx="12" cy="12" r="9.5"/>', '<path d="M2.5 12h19"/>', '<path d="M12 2.5a14 14 0 0 1 3.8 9.5A14 14 0 0 1 12 21.5 14 14 0 0 1 8.2 12 14 14 0 0 1 12 2.5z"/>'],
    mail: ['<rect x="2.5" y="4.5" width="19" height="15" rx="2.5"/>', '<path d="m3 6 9 6 9-6"/>'],
    zap: ['<path d="M13 2 4 13h7l-1 9 9-11h-7l1-9z"/>'],
    shield: ['<path d="M12 2.5 20 6v6c0 5-3.4 8-8 9.5C7.4 20 4 17 4 12V6z"/>', '<path d="m9 12 2 2 4-4"/>'],
    key: ['<circle cx="7.5" cy="15.5" r="4.5"/>', '<path d="m10.8 12.2 9-9"/>', '<path d="m15.5 7.5 2.5 2.5"/>', '<path d="m18.5 4.5 2.5 2.5"/>'],
    pin: ['<path d="M20 10.5c0 6-8 11.5-8 11.5s-8-5.5-8-11.5a8 8 0 0 1 16 0z"/>', '<circle cx="12" cy="10.5" r="2.8"/>'],
    camera: ['<path d="M14.5 4.5h-5l-2 2.5H4a2 2 0 0 0-2 2v8.5a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3.5z"/>', '<circle cx="12" cy="13" r="3.2"/>'],
    file: ['<path d="M14 2.5H6.5a2 2 0 0 0-2 2v15a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V8z"/>', '<path d="M14 2.5V8h5.5"/>', '<path d="M8.5 13h7M8.5 17h7M8.5 9.5H10"/>'],
    lock: ['<rect x="4" y="10.5" width="16" height="10.5" rx="2.5"/>', '<path d="M7.5 10.5V7a4.5 4.5 0 0 1 9 0v3.5"/>'],
    alert: ['<path d="m21.6 18-8-14a2 2 0 0 0-3.5 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.6-3z"/>', '<path d="M12 9.5v4M12 17h.01"/>'],
    check: ['<path d="M21.8 11.3V12a9.8 9.8 0 1 1-5.8-9"/>', '<path d="m9 11.5 3 3 9.5-9.5"/>'],
    info: ['<circle cx="12" cy="12" r="9.5"/>', '<path d="M12 16.5v-5M12 7.8h.01"/>'],
    download: ['<path d="M21 15.5V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3.5"/>', '<path d="m7.5 11 4.5 4.5 4.5-4.5"/>', '<path d="M12 15V3"/>'],
    arrow: ['<path d="M5 12h13"/>', '<path d="m12.5 5.5 6.5 6.5-6.5 6.5"/>'],
    upload: ['<path d="M12 20v-9"/>', '<path d="m8 14 4-4 4 4"/>', '<path d="M20.5 16.8A4.8 4.8 0 0 0 18 8h-1.3A7.5 7.5 0 1 0 4 15.4"/>'],
    cpu: ['<rect x="5" y="5" width="14" height="14" rx="2.5"/>', '<rect x="9" y="9" width="6" height="6" rx="1"/>', '<path d="M9 2.5v2.5M15 2.5v2.5M9 19v2.5M15 19v2.5M2.5 9H5M2.5 15H5M19 9h2.5M19 15h2.5"/>'],
    github: ['<path d="M12 2.5a9.5 9.5 0 0 0-3 18.5c.5.1.7-.2.7-.5v-1.7c-2.6.6-3.2-1.1-3.2-1.1-.4-1.1-1-1.4-1-1.4-.9-.6 0-.6 0-.6 1 .1 1.5 1 1.5 1 .9 1.5 2.3 1.1 2.9.8.1-.6.3-1.1.6-1.3-2.1-.2-4.3-1-4.3-4.6 0-1 .4-1.9 1-2.5-.1-.3-.4-1.2.1-2.5 0 0 .8-.3 2.7 1a9.3 9.3 0 0 1 5 0c1.9-1.3 2.7-1 2.7-1 .5 1.3.2 2.2.1 2.5.6.6 1 1.5 1 2.5 0 3.6-2.2 4.4-4.3 4.6.3.3.6.9.6 1.8v2.7c0 .3.2.6.7.5A9.5 9.5 0 0 0 12 2.5z"/>']
  };

  UPSEC.icon = function (name, cls) {
    var paths = P[name] || P.info;
    if (!Array.isArray(paths)) paths = P.img;
    var extra = cls ? (' ' + cls) : '';
    return '<svg class="i' + extra + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
      'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      paths.join('') + '</svg>';
  };
})();
