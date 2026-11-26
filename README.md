# ssh-kex-tarpit

SSH tarpit posing as OpenSSH. Bots see a normal banner, then hang in the key exchange until they give up.

## How it works

1. Sends `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`.
2. Sends a KEXINIT with OpenSSH 9.6p1's algorithm lists, one byte every 2 s.
3. Its header claims 32 KiB, padded with fake language names. A client waits for the full packet until its own timeout (or the full 18 hours).
4. The key exchange reply follows the same way, but its last byte is never sent.

```
$ ssh -v example.com
debug1: Remote protocol version 2.0, remote software version OpenSSH_9.6p1 Ubuntu-3ubuntu13.20
debug1: SSH2_MSG_KEXINIT sent
(hangs)
```

[endlessh](https://github.com/skeeto/endlessh) sends junk lines before the banner instead.

## Security

- Never reads client data.
- Runs without capabilities and sees only `/usr`, read-only.
- Its only network access is the listening socket from systemd. It can accept clients there, but it can't open connections.
- Limited to 4096 clients, 32 per IP, 128 MB of memory and 25% CPU.

Requires systemd 248+ and Python 3.9+.

## Install

Move sshd off port 22 first.

```
git clone https://github.com/EinBaum/ssh-kex-tarpit.git
cd ssh-kex-tarpit
```

Arch:

```
(cd arch && makepkg -si)
sudo systemctl enable --now ssh-kex-tarpit.socket
```

Other distros:

```
sudo install -Dm755 ssh-kex-tarpit /usr/bin/ssh-kex-tarpit
sudo install -Dm644 -t /etc/systemd/system systemd/ssh-kex-tarpit.{socket,service}
sudo mkdir -p /usr/share/ssh-kex-tarpit/root
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-kex-tarpit.socket
```

## Options

```
--version-line  banner to send, default: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20 (the KEXINIT matches 9.6p1)
--delay         seconds between bytes, default: 2
--max-clients   connections held at once, default: 4096, limited by LimitNOFILE
--max-per-ip    connections per IPv4 address or IPv6 /64, default: 32
--log-after     seconds to wait after an address leaves before logging it, default: 600
--version       print the version and exit
```

Set them with `sudo systemctl edit ssh-kex-tarpit.service`:

```
[Service]
ExecStart=
ExecStart=/usr/bin/ssh-kex-tarpit --delay 5 --version-line "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
```

Quote values with spaces.

To change the port, override `ListenStream=` in `ssh-kex-tarpit.socket` the same way.

## Logs

```
$ journalctl -u ssh-kex-tarpit
203.0.113.7: 1 connection, held 1h00m
2001:db8:5:1::2a: 82 connections in 2h29m, held 14m10s in total, longest 20s
198.51.100.23: 2 connections in 1h00m, held 36h26m in total, longest 18h13m, 30 still held, 41 refused
192.0.2.44: 3 connections in 6m12s, held 5m50s in total, longest 4m01s (shutdown)
4000 other addresses: 4000 connections, held 12s in total
```

An address is logged 10 minutes after it leaves, or every hour while it stays or keeps coming back.

At most 256 addresses are logged per 10 minutes. The rest are summed up in one line. Limit messages are logged at most once per 10 minutes. The per-IP message is logged once per address, and again only after all its connections have closed.

## Test

```
systemd-socket-activate -l 2222 ./ssh-kex-tarpit   # then: ssh -v -p 2222 localhost
test/run-tests.sh
sudo test/system-tests.sh   # installs the units, disposable machines only
```

## Uninstall

Arch:

```
sudo systemctl disable --now ssh-kex-tarpit.socket ssh-kex-tarpit.service
sudo pacman -R ssh-kex-tarpit
```

Other distros:

```
sudo systemctl disable --now ssh-kex-tarpit.socket ssh-kex-tarpit.service
sudo rm /usr/bin/ssh-kex-tarpit /etc/systemd/system/ssh-kex-tarpit.{socket,service}
sudo rm -r /usr/share/ssh-kex-tarpit
sudo systemctl daemon-reload
```

## License

MIT
