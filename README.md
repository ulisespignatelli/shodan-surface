# Shodan Surface — Monitor de exposición 🛰️

Panel **hosteado y automático** de superficie de exposición. Un workflow de GitHub Actions consulta [Shodan](https://www.shodan.io/) por **tus activos**, y GitHub Pages muestra el dashboard — con puertos, **CVEs conocidas** y **protocolos industriales (OT)**. Mismo patrón que [VulnWatch](https://github.com/ulisespignatelli/vulnwatch): la API key vive en los *Secrets* de Actions, nunca en el navegador.

🔗 **Demo en vivo:** https://ulisespignatelli.github.io/shodan-surface/

Por [Ulises Pignatelli](https://github.com/ulisespignatelli) — UP Security.

---

## Cómo funciona

```
targets.txt  ─▶  collect.py (en GitHub Actions, con tu SHODAN_API_KEY)  ─▶  site/data/surface.json  ─▶  GitHub Pages
```

1. Vos listás tus activos en `targets.txt`.
2. Cada 12 h (o cuando lo dispares), Actions corre `collect.py`, consulta Shodan y genera el JSON.
3. Pages sirve el dashboard estático que lee ese JSON. **El visitante nunca ve tu key** (no hay servidor en el navegador que la pueda leer).

> Por eso es solo para **tus activos fijos** (monitoreo), no para escribir cualquier dominio en vivo. Para eso necesitás un proxy serverless; esta versión es la más limpia y segura para un portfolio.

## Puesta en marcha

1. **Subí este repo** a GitHub.
2. **Agregá tu API key como secret**: Settings → Secrets and variables → **Actions** → *New repository secret* → nombre `SHODAN_API_KEY`, valor tu key de Shodan.
3. **Activá Pages**: Settings → Pages → Source: **GitHub Actions**.
4. **Editá `targets.txt`** con tus dominios/IPs (uno por línea).
5. Corré el workflow (Actions → *Actualizar superficie* → *Run workflow*) o esperá al cron.

> Sin el secret, el workflow genera **datos de ejemplo** igual, así ves el panel funcionando desde el primer deploy.

## Qué muestra

- **Overview**: activos monitoreados, puertos abiertos, CVEs y protocolos OT, con tarjeta por activo.
- **Detalle por activo**: IP, organización, ISP/ASN, ubicación, hostnames; **alerta OT** si hay protocolos industriales expuestos (Modbus, S7, DNP3, BACnet…); CVEs enlazadas a NVD; servicios con banner.

## Probar localmente

```bash
python3 collect.py --demo                 # genera datos de ejemplo
cd site && python3 -m http.server 8000    # abrí http://localhost:8000
```

## Ética y alcance

Shodan recopila estos datos de forma **pasiva**; esta herramienta solo los ordena. Monitoreá **únicamente activos propios o que estés autorizado a auditar**. Es defensa (saber qué exponés para cerrarlo), no ataque. Cuidá los créditos de tu plan: el cron por defecto es cada 12 h.

## Estructura

```
shodan-surface/
├── collect.py                  # recolector (corre en Actions)
├── targets.txt                 # tus activos a monitorear
├── .github/workflows/update.yml
└── site/                       # dashboard estático (Pages)
    ├── index.html  ·  css/  ·  js/  ·  data/surface.json
```

## Licencia

MIT — ver [LICENSE](LICENSE).
