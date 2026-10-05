# AWG Control для MikroTik hAP ac²

AmneziaWG и веб-панель в одном контейнере: импорт и переключение VPN-профилей, маршруты Direct / Geo / VPN для отдельных устройств, управление кнопками и индикатором USR.

## Установка

На компьютере нужны **Git, Python 3.10+ и запущенный Docker с Linux-контейнерами**. На роутере — **RouterOS 7.24.5 stable, пакет container, USB ext4 и работающий интернет**. [Подготовка роутера →](GOTCHAS.md#подготовка-роутера)

Запусти на компьютере, подключённом к LAN MikroTik:

**Windows — PowerShell 7:**

```powershell
git clone https://github.com/william-aqn/microtik-awg3-installer.git &&
cd microtik-awg3-installer &&
python -m venv .venv &&
.\.venv\Scripts\python.exe -m pip install paramiko==4.0.0 &&
.\.venv\Scripts\python.exe panel/install.py
```

**Linux / macOS:**

```sh
git clone https://github.com/william-aqn/microtik-awg3-installer.git &&
cd microtik-awg3-installer &&
python3 -m venv .venv &&
.venv/bin/python -m pip install paramiko==4.0.0 &&
.venv/bin/python panel/install.py
```

Мастер спросит адрес и пароль роутера, LAN, USB и пароль панели; соберёт и установит **контейнер с VPN и панелью, маршруты, firewall, кнопки и USR**.

После установки открой **`http://<LAN-IP-роутера>:8088`** — например, [192.168.3.1:8088](http://192.168.3.1:8088). Войди с заданным паролем, выбери **Import profile → свой `.conf` → Save profile → Connect**. В **Devices** назначаются режимы устройств, в **Geo lists** — списки для Geo. По умолчанию после подключения весь интернет LAN идёт через VPN.

## Кнопки

| Кнопка | Действие |
|---|---|
| **Mode у USB** | Включить/отключить VPN; если контейнер остановлен — запустить его |
| **Reset/WPS у питания**, коротко до 1 секунды | Две вспышки USR и полная остановка контейнера, включая панель |
| **USR горит** | У VPN есть недавний handshake; погас — соединение не подтверждено или выключено |

**Reset нажимай только на уже работающем роутере, не при включении питания.**

[Работа с панелью и скриншот →](panel/README.md) · [Подготовка, ограничения и диагностика →](GOTCHAS.md)
