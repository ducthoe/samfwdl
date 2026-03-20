# samfwdl

```bash
python -m samfwdl checkupdate SM-S721B EUX
python -m samfwdl download SM-S721B EUX -o ./downloads --resume
python -m samfwdl download SM-S721B EUX -o ./downloads --decrypt
python -m samfwdl download SM-S721B EUX --firmware S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2 --force-firmware -o ./downloads
python -m samfwdl decrypt SM-S721B EUX ./file.zip.enc4 -o ./file.zip
python -m samfwdl decrypt SM-S721B EUX ./file.zip.enc4 --firmware S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2 --force-firmware -o ./file.zip
```

```bash
pip install .
```

```bash
python -m samfwdl --help
```

