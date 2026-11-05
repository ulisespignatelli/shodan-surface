/* Shodan Surface (hosteado) — lee site/data/surface.json (generado por Actions)
   y muestra un panel multi-activo: overview + detalle por activo. */
(function () {
  var ic = function (n) { return UPSEC.icon(n); };
  var view = document.getElementById("view");
  var DATA = null;

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }
  function secHead(t) { return '<div class="sec-head"><h2>' + esc(t) + '</h2><div class="rule"></div></div>'; }
  function fmtDate(s) { try { return new Date(s).toLocaleString("es-AR", { dateStyle: "medium", timeStyle: "short" }); } catch (e) { return s; } }

  // ---------- OVERVIEW ----------
  function assetCard(a, i) {
    var tags = "";
    if (a.vulns.length) tags += '<span class="tag-cve">' + a.vulns.length + " CVE" + (a.vulns.length > 1 ? "s" : "") + "</span>";
    if (a.ot.length) tags += ' <span class="tag-ot">OT · ' + a.ot.length + "</span>";
    return '<a class="tool" href="#/asset/' + i + '">' +
      '<div class="ic">' + ic(a.ot.length ? "zap" : "globe") + "</div>" +
      "<h3>" + esc(a.label) + "</h3>" +
      '<p>' + esc(a.org) + " · " + esc(a.ip) + "</p>" +
      '<div class="impacts" style="margin-top:12px">' +
        '<span class="imp">' + a.ports.length + " puertos</span>" + tags +
      "</div>" +
      '<span class="cta">Ver detalle' + ic("arrow") + "</span></a>";
  }

  function overview() {
    var d = DATA;
    var t = d.totals;
    var demo = d.demo ? '<div class="demo-badge">' + ic("info") + "Datos de ejemplo (modo demo). Configurá SHODAN_API_KEY y targets.txt para datos reales.</div>" : "";
    var errs = (d.errors && d.errors.length)
      ? '<div class="alert warn" style="margin-top:8px">' + ic("alert") + "<div><b>" + d.errors.length + " activo(s) con problemas:</b> " +
        d.errors.map(function (e) { return esc(e.target) + " (" + esc(e.error) + ")"; }).join(", ") + "</div></div>"
      : "";
    var tiles = '<div class="tiles">' +
      '<div class="tile"><b>' + t.assets + "</b><span>Activos monitoreados</span></div>" +
      '<div class="tile"><b>' + t.ports + "</b><span>Puertos abiertos</span></div>" +
      '<div class="tile ' + (t.vulns ? "bad" : "") + '"><b>' + t.vulns + "</b><span>CVEs conocidas</span></div>" +
      '<div class="tile ' + (t.ot ? "ot" : "") + '"><b>' + t.ot + "</b><span>Protocolos OT expuestos</span></div>" +
      "</div>";
    view.innerHTML =
      '<section class="hero" style="padding:46px 0 6px">' +
        '<div class="eyebrow"><span class="dot"></span> Attack Surface Monitoring</div>' +
        '<h1 style="font-size:38px">Tu <span class="g">superficie de exposición</span>, monitoreada</h1>' +
        '<p class="sub">Lo que Shodan ve expuesto en tus activos: puertos, CVEs y protocolos OT. Se actualiza solo.</p>' +
      "</section>" +
      demo +
      '<div class="hint" style="text-align:center;margin-bottom:6px">Última actualización: ' + esc(fmtDate(d.generated_at)) + "</div>" +
      tiles + errs +
      secHead("Activos (" + d.assets.length + ")") +
      '<div class="grid">' + d.assets.map(assetCard).join("") + "</div>";
  }

  // ---------- DETALLE ----------
  function metaGrid(d) {
    var items = [
      ["IP", d.ip], ["Organización", d.org], ["ISP", d.isp], ["ASN", d.asn],
      ["Ubicación", (d.city ? d.city + ", " : "") + d.country],
      ["Hostnames", d.hostnames.length ? d.hostnames.join(", ") : "—"],
      ["Sistema operativo", d.os],
      ["Visto por Shodan", d.last_update ? d.last_update.replace("T", " ").slice(0, 16) : "—"],
    ];
    return '<div class="meta-grid">' + items.map(function (it) {
      return '<div><div class="k">' + esc(it[0]) + '</div><div class="v">' + esc(it[1] || "—") + "</div></div>";
    }).join("") + "</div>";
  }
  function cveLinks(list) {
    if (!list.length) return "";
    return '<div class="cve-list">' + list.map(function (c) {
      return '<a href="https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(c) + '" target="_blank" rel="noopener">' + esc(c) + "</a>";
    }).join("") + "</div>";
  }
  function otBanner(d) {
    if (!d.ot.length) return "";
    var chips = d.ot.map(function (o) { return '<span class="otchip">' + esc(o.label) + " · :" + o.port + "</span>"; }).join("");
    return '<div class="otbanner">' + ic("zap") +
      "<div><b>Protocolos industriales (OT) expuestos a internet.</b> Controlan procesos físicos y no deberían ser accesibles públicamente. Priorizá segmentarlos." +
      '<div class="otchips">' + chips + "</div></div></div>";
  }
  function services(d) {
    return d.services.map(function (s, i) {
      var tags = "";
      if (s.vulns && s.vulns.length) tags += '<span class="tag-cve">' + s.vulns.length + " CVE" + (s.vulns.length > 1 ? "s" : "") + "</span>";
      if (d.ot.some(function (o) { return o.port === s.port; })) tags += '<span class="tag-ot">OT</span>';
      var ver = s.version ? " " + esc(s.version) : "";
      var mod = s.module ? '<span class="mod">(' + esc(s.module) + ")</span>" : "";
      var inner = (s.banner ? "<pre>" + esc(s.banner) + "</pre>" : "") + (s.vulns && s.vulns.length ? cveLinks(s.vulns) : "");
      if (!inner) inner = '<div class="hint" style="margin:12px 0 0">Sin banner adicional.</div>';
      return '<div class="svc"><div class="svc-h" data-i="' + i + '"><span class="port">' + esc(s.port) + "/" + esc(s.transport) +
        '</span><span class="svc-name">' + esc(s.product) + ver + " " + mod + '</span><span class="svc-tags">' + tags +
        '</span></div><div class="banner" id="b' + i + '">' + inner + "</div></div>";
    }).join("");
  }
  function detail(idx) {
    var d = DATA.assets[idx];
    if (!d) { view.innerHTML = '<div class="alert warn">' + ic("alert") + "<div>Activo no encontrado. <a href='#/' style='color:var(--brand)'>Volver</a>.</div></div>"; return; }
    var vulnSec = d.vulns.length ? secHead("Vulnerabilidades conocidas (" + d.vulns.length + ")") + cveLinks(d.vulns) : "";
    view.innerHTML =
      '<a class="crumb" href="#/" style="margin-top:30px">' + ic("arrow") + " Volver al panel</a>" +
      '<div class="mod-head"><div class="ic">' + ic(d.ot.length ? "zap" : "globe") + '</div><h2>' + esc(d.label) + "</h2></div>" +
      '<div class="mod-sub">' + esc(d.org) + " · " + esc(d.ip) + "</div>" +
      metaGrid(d) + otBanner(d) + vulnSec +
      secHead("Servicios expuestos (" + d.services.length + ")") + services(d);
    view.querySelectorAll(".svc-h").forEach(function (h) {
      h.addEventListener("click", function () {
        var b = document.getElementById("b" + h.getAttribute("data-i"));
        b.className = b.className.indexOf("on") > -1 ? "banner" : "banner on";
      });
    });
  }

  function route() {
    window.scrollTo(0, 0);
    var m = (location.hash || "#/").match(/^#\/asset\/(\d+)/);
    if (m) detail(parseInt(m[1], 10)); else overview();
  }

  fetch("data/surface.json", { cache: "no-store" })
    .then(function (r) { return r.json(); })
    .then(function (j) { DATA = j; route(); window.addEventListener("hashchange", route); })
    .catch(function (e) {
      view.innerHTML = '<div class="alert warn" style="margin-top:30px">' + ic("alert") +
        "<div>No se pudo cargar los datos (<code>data/surface.json</code>). Si es la primera vez, esperá a que corra el workflow de Actions.</div></div>";
    });
})();
