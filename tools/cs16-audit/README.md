# Auditor de servidores de CS 1.6

Consulta la lista por Steamworks, mide respuestas UDP desde tu PC y exporta
IPs con indicios de SPAM. No necesita copiar filas del navegador, conectarse a
una partida ni descargar contenido de los servidores. Python 3.10+ de 64 bits;
sin paquetes externos. La consulta del cliente necesita Windows, Steam abierto
y una `steam_api64.dll` oficial ya instalada. En esta PC detecta la DLL de CS2.

## Ejecutar

Desde `C:\Developer\Opensource\goldsrc-fake-servrs-firewall`:

```powershell
python tools\cs16-audit\audit.py
```

El ping predeterminado es **estrictamente menor a 100 ms**. Si `python` apunta
a otra instalación, en esta PC también se puede ejecutar con
`C:\Developer\Pythons\Python310\python.exe`.

La detección automática busca las bibliotecas de Steam. Si necesitás indicar
la DLL:

```powershell
python tools\cs16-audit\audit.py --steam-api "F:\SteamLibrary\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\steam_api64.dll"
```

Para repetir el análisis de una lista guardada:

```powershell
python tools\cs16-audit\audit.py --input tools\cs16-audit\results-first-batch\discovery.json
```

## Actualizar y publicar la blacklist

Cada auditoría terminada agrega al `blacklisted_iplist.json` de la raíz las IPs
`spam` o `sospechoso` con ping medido **menor a 100 ms**. Los endpoints vacíos
no se agregan. Se compara contra todos los grupos; no se duplica ninguna IP
nueva ni se quita/reordena ninguna entrada existente. Las IPs nuevas se
agrupan en `CS 1.6 automated audit`. Una ejecución sin novedades no reescribe
el archivo. La actualización usa reemplazo atómico y valida todas las IPs
antes de escribir. Un lock impide que dos ejecuciones pierdan agregados al
escribir a la vez. Si una ejecución termina abruptamente y deja un `.lock`,
quitá ese archivo sólo después de verificar que ya no sigue ejecutándose. Ctrl+C conserva el informe y no actualiza el JSON.

Para agregar los resultados ya guardados, sin repetir el escaneo:

```powershell
python tools\cs16-audit\audit.py --from-report tools\cs16-audit\results-first-batch\report.json
```

Para auditar, actualizar, commitear y pushear a `origin/main`:

```powershell
python tools\cs16-audit\audit.py --publish
```

También funciona `--from-report RUTA --publish`. La publicación requiere
estar en `main`, sin cambios staged y con HEAD igual a `origin/main` luego de
un fetch. Sólo incluye el JSON en el commit; usa la fecha local en
`feat: blacklist updated (YYYY-MM-DD)` y push sin force. Sin cambios en el
JSON no crea un commit. Si falla el push, el commit queda local; revisá el
error y usá `git push origin main` para reintentar.

`--no-update-blacklist` permite generar sólo informes y `--blacklist RUTA`
permite elegir otro JSON compatible (publicar requiere el JSON del repo).
Los resultados locales y el entorno Python no se versionan. Las detecciones
heurísticas incluyen sospechas y el informe mantiene su evidencia y alcance;
un lote parcial también puede aportar IPs nuevas, sin declarar cobertura total.

## Reglas acordadas

- **0 jugadores:** `seguro_por_regla_usuario`. Se salta la consulta detallada.
  Es la regla solicitada por el usuario, no una verificación independiente de
  seguridad. Se aplica por endpoint, no a todos los puertos de esa IP.
- **Más de 32 jugadores anunciados:** `spam`.
- **1–32 jugadores:** cuatro rondas de INFO → PLAYER → INFO. Marca como
  `sospechoso` las rotaciones repetidas de nombre y mapa en consultas
  consecutivas, SteamIDs cambiantes, campos incompatibles con CS 1.6 o
  contradicciones repetidas entre conteo y lista de jugadores. Se compara la
  lista sólo si nombre, mapa, conteo y bots permanecieron iguales entre las
  dos respuestas INFO que rodean la consulta de jugadores.
- Un cambio normal de mapa, jugadores o un timeout no basta para acusar SPAM.
  Una consulta de jugadores bloqueada/no respondida es distinta de una
  respuesta válida con una lista vacía. Mediciones insuficientes son
  `inconcluso`; `sin_indicios` tampoco significa una garantía de seguridad.

Primero se seleccionan las respuestas con ping menor a 100 ms en Steam.
Las reglas rápidas usan ese ping; el análisis detallado usa la mediana de
los tiempos A2S_INFO. `--probe-all` también mide entradas con ping alto o sin
respuesta en Steam, para reducir omisiones del prefiltrado.

Como el resultado solicitado son **IPs**, al detectar SPAM/sospecha en un
puerto el script deja de consultar otros puertos de esa IP. Esos puertos
omitidos no se etiquetan como fraudulentos. `--all-ports` desactiva esa
optimización. El informe indica cuántos puertos no se midieron por esa razón.
Concurrencia: 12 IPs; 30 consultas/s globales y separación por IP. Consultas,
fragmentos, challenges y descompresión tienen límites de tiempo/tamaño.

## Archivos generados

Cada ejecución crea una carpeta `results-fecha-hora`:

- `suspicious-ips.txt`: IPs únicas con al menos un endpoint SPAM/sospechoso.
- `suspicious-endpoints.txt`: los IP:puerto que tienen evidencia concreta.
- `safe-zero-player-endpoints.txt`: endpoints vacíos clasificados por tu regla.
- `report.json`: mediciones, errores, motivos y alcance de la consulta.
- `report.csv`: resumen para revisar en una hoja de cálculo.
- `discovery.json`: lista original recibida y estado de la consulta.

Guarda resultados intermedios cada diez segundos. Ctrl+C guarda los grupos
de IP ya terminados y marca la ejecución como parcial.

## Límite de Steam y obtener una lista más amplia

**En la prueba real el cliente devolvió exactamente 10.000 entradas y no
terminó dentro de 90 segundos. La lista obtenida no es completa.** El script
marca `metadata.partial` si la consulta no termina o si recibe 10.000 o más
entradas. No presenta ese resultado como todas las IPs del master.

El script también ofrece `--web-api` usando una clave propia de Steam Web API
configurada en la variable de entorno `STEAM_WEB_API_KEY`:

```powershell
python tools\cs16-audit\audit.py --web-api
```

Pide hasta 50.000 entradas por lote y, si se llena el lote, solicita más
excluyendo las IPs ya recibidas. Si la exclusión no funciona, queda marcado
como incompleto. Esta paginación busca cubrir **IPs**, no necesariamente
todos los puertos de una IP que ya apareció. La clave no se imprime ni se
guarda en los informes. Esta vía requiere una clave válida: la prueba sin
clave devolvió HTTP 403, y no se pudo verificar aquí una ejecución real
autenticada. `GetServerList` es un endpoint usado por el servicio de Steam,
pero no está documentado en la página pública de `IGameServersService`.
No se promete una detección infalible de todos los scams: un servidor puede
falsificar todas las respuestas de manera consistente.

## Investigación

- [API oficial del navegador de Steam](https://partner.steamgames.com/doc/api/ISteamMatchmakingServers):
  `RequestInternetServerList`, `GetServerCount`, `GetServerDetails` y
  `ReleaseRequest`. AppID de CS 1.6: 10.
- [Reporte en el repositorio de Valve sobre conteos falsificados](https://github.com/ValveSoftware/halflife/issues/3805):
  muestra discrepancias entre el master y A2S_INFO. Es un reporte técnico;
  no demuestra que cada discrepancia actual sea fraude.
- [ValvePython: acceso al servicio GameServers](https://github.com/ValvePython/steam/blob/master/steam/client/builtins/gameservers.py):
  `GameServers.GetServerList#1`, filtros y límite de resultados.
- [Headers del SDK usados para comprobar el ABI](https://github.com/Facepunch/Facepunch.Steamworks/tree/master/Generator/steam_sdk):
  `isteammatchmaking.h`, `matchmakingtypes.h` y `steamclientpublic.h`.
- [Implementación A2S de referencia](https://github.com/Yepoleb/python-a2s):
  consultas INFO/PLAYER y challenges. Este script usa un parser propio con
  soporte para paquetes fragmentados Source/GoldSrc y sin dependencias.

## Verificación

```powershell
python -m unittest discover -s tools\cs16-audit -p "test_*.py" -v
```

Las pruebas usan Arrange, Act, Assert y verifican formatos de paquetes,
fragmentación, límites, clasificación, casos normales que no deben acusarse
y paginación que no debe declarar una lista completa cuando se ignora el
filtro. Los resultados iniciales reales están en `results-first-batch`.
