# Rex's Ghost Recon

![A masked figure in a black suit and red tie stands with an armored wolf in the rain.](header.jpg)

Public-record desk from WolfSec. Not affiliated with Ubisoft. No exploit pack, no password guessing, no vulnerability scripts.

**[Open the live desk](https://masterxhackerx420-oss.github.io/rex-ghost-recon/)** — the browser desk with every module: DNS, registration, headers, frame policy, robots.txt, links, network home, stack hint, certificate, cert log, reachability, and redirects. Authorized hosts only. Reading another site's page, and any port check, still runs on the installed copy.

Use it only on hosts you are allowed to inspect. Python 3.9 or newer. Nothing to pip install.

## Install

| Platform | Download |
| --- | --- |
| Windows | [rex-ghost-recon-windows.zip](https://github.com/masterxhackerx420-oss/rex-ghost-recon/releases/download/v1.0.0/rex-ghost-recon-windows.zip) |
| macOS | [rex-ghost-recon-macos.zip](https://github.com/masterxhackerx420-oss/rex-ghost-recon/releases/download/v1.0.0/rex-ghost-recon-macos.zip) |
| Linux | [rex-ghost-recon-linux.zip](https://github.com/masterxhackerx420-oss/rex-ghost-recon/releases/download/v1.0.0/rex-ghost-recon-linux.zip) |
| Debian / Ubuntu | [rex-ghost-recon_1.0.0_all.deb](https://github.com/masterxhackerx420-oss/rex-ghost-recon/releases/download/v1.0.0/rex-ghost-recon_1.0.0_all.deb) |
| Android (Termux) | [rex-ghost-recon-android.zip](https://github.com/masterxhackerx420-oss/rex-ghost-recon/releases/download/v1.0.0/rex-ghost-recon-android.zip) |

Windows: unzip, then `powershell -ExecutionPolicy Bypass -File install\windows.ps1`

macOS: unzip, then `sh install/macos.sh`

Linux: unzip, then `sh install/linux.sh`

Debian or Ubuntu, if you want the package instead:

```sh
sudo dpkg -i rex-ghost-recon_1.0.0_all.deb
```

Android: install [Termux](https://termux.dev), unzip there, then `sh install/android.sh`

Run `rex-ghost-recon`. Local desk, bound to this machine only: `rex-ghost-recon --web`, then open http://127.0.0.1:8787

## Menu

```text
1 DNS            2 Registration     3 Headers
4 Frame policy   5 robots.txt       6 Links
7 Network home   8 Stack hint       9 Certificate
10 Cert log      11 Ports           12 Traceroute
13 Nmap top 50, only if nmap is already installed
a  all public records
```

One shot, no menu:

```sh
rex-ghost-recon --once example.com 1,3,9
```

Nmap, when you already have it, is a top-50 open-port check with no scripts. Traceroute uses the `traceroute` command if it is installed.
