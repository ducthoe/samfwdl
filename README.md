<!--
Copyright (C) 2026 ducthoe
SPDX-License-Identifier: GPL-3.0-only
-->

# asgard

```bash
python -m asgard checkupdate SM-S721B EUX
python -m asgard history SM-S721B EUX
python -m asgard download SM-S721B EUX -o ./downloads --resume
python -m asgard download SM-S721B EUX -o ./downloads --decrypt
python -m asgard download SM-S721B EUX --firmware S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2 --force-firmware -o ./downloads
python -m asgard decrypt SM-S721B EUX ./file.zip.enc4 -o ./file.zip
python -m asgard decrypt SM-S721B EUX ./file.zip.enc4 --firmware S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2 --force-firmware -o ./file.zip
```

```bash
pip install .
```

```bash
python -m asgard --help
```
