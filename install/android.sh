#!/data/data/com.termux/files/usr/bin/sh
# Rex's Ghost Recon — Android via Termux. Not a Play Store app.
set -eu
if ! command -v pkg >/dev/null 2>&1; then
  echo "Run this inside Termux. Android itself does not ship Python." >&2
  exit 1
fi
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
root=$here
[ -f "$root/rex_ghost_recon.py" ] || root=$here/..
[ -f "$root/rex_ghost_recon.py" ] || { echo "rex_ghost_recon.py is not next to this installer" >&2; exit 1; }
[ -f "$root/assets/crew.jpg" ] || { echo "assets/crew.jpg is missing" >&2; exit 1; }
pkg install -y python
prefix=${PREFIX:-$HOME}
mkdir -p "$prefix/bin" "$HOME/.local/share/rex-ghost-recon/assets"
cp "$root/rex_ghost_recon.py" "$prefix/bin/rex-ghost-recon"
chmod 755 "$prefix/bin/rex-ghost-recon"
cp "$root/assets/crew.jpg" "$HOME/.local/share/rex-ghost-recon/assets/crew.jpg"
echo "Installed $prefix/bin/rex-ghost-recon"
echo "Run: rex-ghost-recon"
echo "Local desk: rex-ghost-recon --web"
