# goldsrc-fake-servers-firewall
A repository listing all the IP address listing fake, bloaty servers, and creates a firewall rule on Windows, blocking them on the spot.

# The problem

Since the SteamPIPE update in 2013, which would bring the GoldSrc's query system as the same as all Source-based games, Counter-Strike 1.6 suffered from an exploit that would flood the masterservers with fake servers, deceiving players by redirecting all of them to a single, central server. Their purposes would be to scam people with fake, and potentially steal players' SteamIDs to simulate fake "active players". 

Here is a small example of how the serverlist looks in CS 1.6 :
![A small example of fake servers](https://raw.githubusercontent.com/mehLabs/goldsrc-fake-servers-firewall/main/assets/serverbrowser.png)

This problem does not only target Counter-Strike 1.6, but also Counter-Strike: Source, Half-Life 2: Deathmatch, Team-Fortress 2, Left 4 Dead 2, and even Counter-Strike 2, which present the same problematic issues as CS 1.6.

Despite being repeatedly reported on VALVe's Github repositories, and that the community insists it is a critical issue, **VALVe does not believe this is a problem, and is refusing to fix it since a whole decade**. On the contrary, according to them, their solution to prevent these from happening would simply to use a server token (GSLT) that you would generate along with the APPID to prove you made the server, as it has to be unique between each server. But, it only supports 3 games: TF2, CS2 and Garry's Mod, and does not fully fix the issue in the first place, especially on TF2's quickplay menu.

To make matters worse, this problem has been recently extended in Half-Life, shortly after the 25th anniversary update, where almost 75% of the servers listed were redirected to a single static server. 

Unfortunately for the community, and unlike any Source-based game, the GoldSRC's serverbrowser does not have any blacklisting options, meaning that blocking these fake servers within the game is **outright impossible**. 

# The Solution

Sadly, there isn't much to do engine-sided. The only solution to prevent seeing these fake servers is to get their IPs, and block outgoing connections to these IPs with a firewall rule.

This project was thus made to block these servers directly through a rule on your Windows firewall, so that it gets immediately filtered by your system, resulting in more honest servers.

# The only drawback

The problem with blocking all of these fake servers is that VALVe isn't aware of this happening when sending them to the player. As a result, it might take a whole lot of time to display all servers. 

We recommend you from adding any server to your favorites, so you can see them faster.

# Running the script

Open a Powershell window as an administrator (WIN + X, then `Windows Powershell (Admin)`). Copy and paste the following command, and run it :

```ps1
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/mehLabs/goldsrc-fake-servers-firewall/main/BlockFakeServers.ps1'))
```

**__One rule of thumb is to always look at the script before running it.__**

In this project's case, it downloads a .json file containing a list of fake IPs, and creates an outbound firewall rule to block them.

If there's already an entry of our Firewall rule, it will recreate it with the newest, updated values.

# Addentum
## Spotting these fake servers

If you have doubts seeing a regular server or a fake server, you can quickly find out with these quick checks:

- Any server that has more than 32 players spots **is guaranteed** to be a fake server. GoldSRC can only support 32 players in a single server.
- Any server that has absurd players statistics (some players having more than 300 frags in less than 30 minutes) **is guaranteed** to be a fake server. You can even hit the refresh key repeatedly, and see absolutely new players with already a high score! 
- When querying a server you think is suspicious, don't hesitate to repeat that operation a few times. If the server name, map or the player counter repeatedly changes, it's a fake server that can be safely blacklisted.

<video src="https://raw.githubusercontent.com/mehLabs/goldsrc-fake-servers-firewall/main/assets/refresh_query.mp4" width="300" />

## How to report fake servers? Is there a false positive detected?

**Please open an issue on Github, along with the IPs you've spotted!**

## What about Source?

Since the original scope of this project is GoldSRC games, we did not plan to include them on the list.

However, the Source Engine includes the ability to blocklist IPs through a file. So, if you are looking for a similar solution for the Source engine, please check out this repository that does the job for you : https://github.com/Ballganda/css-server-blacklist

## Are you planning something similar for Linux / Steam Deck ?

Considering the increasing number of Steam Deck users, this is something we plan creating in a near future.

## Auditor automático de CS 1.6

### Requisitos

- Windows y Python 3.10 o superior **de 64 bits**. No requiere paquetes externos.
- Steam abierto, con tu cuenta iniciada y CS 1.6 original en la biblioteca.
- Una `steam_api64.dll` oficial instalada. El auditor la busca automáticamente en
  las bibliotecas de Steam; en esta PC usa la de CS2. Si no la encuentra, usá
  `--steam-api "RUTA\steam_api64.dll"`.
- Para publicar: Git configurado con tu nombre/email y acceso de escritura a
  `origin`. La rama `main` debe estar sincronizada y no debe haber cambios staged.

### Ejecutar y publicar

Abrí **PowerShell normal**, sin necesidad de administrador. En esta PC el fork
está en `C:\Developer\Opensource\goldsrc-fake-servrs-firewall`:

```powershell
cd C:\Developer\Opensource\goldsrc-fake-servrs-firewall
git switch main
git pull --ff-only
python tools\cs16-audit\audit.py --publish
```

Si `python` no apunta a una instalación de 64 bits compatible, en esta PC podés
reemplazar la última línea por este comando con el Python que usamos:

```powershell
& "C:\Developer\Pythons\Python310\python.exe" tools\cs16-audit\audit.py --publish
```

El comando consulta Steam, analiza servidores con **ping menor a 100 ms** y
agrega las IPs detectadas a `blacklisted_iplist.json`, sin duplicar IPs ni quitar
las existentes. Después crea el commit `feat: blacklist updated (YYYY-MM-DD)` y
pushea a `origin/main`. Sin cambios en el JSON no crea commit.

Los servidores vacíos se saltan; los que anuncian más de 32 jugadores se marcan
como SPAM. Para detectar rotación de nombre y/o mapa toma una lectura inicial
y tres refrescos: exige cambios en los tres refrescos consecutivos. Una lectura
igual o fallida corta la secuencia.

Muestra progreso en la terminal y guarda informes en
`tools\cs16-audit\results-fecha-hora`. La consulta puede tardar varios minutos.
Si Steam devuelve un lote incompleto, el informe queda marcado como parcial.
Durante el análisis, Ctrl+C guarda las mediciones terminadas y cancela la
actualización del JSON.

### Otras formas de ejecutar

Auditar y actualizar el JSON local, sin publicar:

```powershell
python tools\cs16-audit\audit.py
```

Auditar y generar únicamente informes:

```powershell
python tools\cs16-audit\audit.py --no-update-blacklist
```

Agregar un informe guardado y publicarlo, sin repetir las consultas:

```powershell
python tools\cs16-audit\audit.py --from-report "RUTA\report.json" --publish
```

Los informes son locales y no se incluyen en Git. Ver [documentación del
auditor](tools/cs16-audit/README.md) para opciones de descubrimiento, filtros,
reglas y pruebas.
