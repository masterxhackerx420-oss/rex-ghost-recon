#!/bin/sh
# Rex's Ghost Recon — macOS. User install, no root.
set -eu
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
root=$here
[ -f "$root/rex_ghost_recon.py" ] || root=$here/..
[ -f "$root/rex_ghost_recon.py" ] || { echo "rex_ghost_recon.py is not next to this installer" >&2; exit 1; }
[ -f "$root/assets/crew.jpg" ] || { echo "assets/crew.jpg is missing" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Python 3.9 or newer is required. Install it from python.org if macOS does not have it." >&2; exit 1; }
mkdir -p "$HOME/.local/bin" "$HOME/.local/share/rex-ghost-recon/assets"
cp "$root/rex_ghost_recon.py" "$HOME/.local/bin/rex-ghost-recon"
chmod 755 "$HOME/.local/bin/rex-ghost-recon"
cp "$root/assets/crew.jpg" "$HOME/.local/share/rex-ghost-recon/assets/crew.jpg"
echo "Installed $HOME/.local/bin/rex-ghost-recon"
echo "Run: rex-ghost-recon"
echo "Local desk: rex-ghost-recon --web"
echo "If the command is not found, add \$HOME/.local/bin to PATH."
