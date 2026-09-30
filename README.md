# CIP-B103 Lab [#] – HTTP Traffic Capture, File Carving & Steganalysis (Rhino Hunt)

**Student:** Fuseini Imoru Kantuogaa **Course:** CIP-B103 **Lab:** Lab [#] – Web Server Traffic Capture & the DFRWS 2005 "Rhino Hunt" Scenario

## Overview

This lab has two parts. The first sets up a local Apache web server, captures the HTTP traffic of a browser request with Wireshark, and inspects the resulting `.pcapng` file. The second part works through the public **DFRWS 2005 "Rhino Hunt"** scenario: securely wiping a test file with `shred`, imaging a USB drive (`RHINOUSB.dd`), carving deleted files from it with PhotoRec and TSK, detecting and breaking JPEG steganography with `stegdetect`/`stegbreak`/`jpseek`, cracking a password-protected ZIP with `fcrackzip`, and analyzing two FTP/HTTP network logs (`rhino2.log`, `rhino.log`) to identify a suspect host, a stolen file and a malicious executable.

## Case Folder Structure

```bash
cd ~/HTTP_Wireshark_Assignment        # Part 1: web server capture
cd ~/HTTP_Wireshark_Assignment/shred  # Part 2: shred test, USB image, rhion/ case folder
cd ~/HTTP_Wireshark_Assignment/shred/rhion              # RHINOUSB.dd, PhotoRec output, logs
cd ~/HTTP_Wireshark_Assignment/shred/rhion/steg          # carved images, stegdetect
cd ~/HTTP_Wireshark_Assignment/shred/rhion/stego-toolkit  # jphide/jpseek install
```

## 1. Web Server Setup & HTTP Capture

Apache's web root was inspected and a test page deployed:

```bash
sudo su
ls -l /var/www/html
chmod 777 /var/www/html
exit
mkdir HTTP_Wireshark_Assignment
cd HTTP_Wireshark_Assignment
nano basic.html
sudo cp basic.html /var/www/html/
sudo systemctl restart apache2
sudo systemctl status apache2
```

`basic.html` contained a heading and the analyst's name:

```html
<!DOCTYPE html>
<html>
<head><title>HTTP Wireshark Forensics</title></head>
<body>
<h1>My First Heading</h1>
<p>Name: Fuseini Imoru</p>
</body>
</html>
```

Apache confirmed active and running (PID 7784, started 2026-09-08 07:36:49 EDT).

A traffic capture directory was created and Wireshark run on the loopback interface while the page was requested:

```bash
mkdir -p ~/traffic
wireshark -i lo -k -w ~/traffic/image2.pcapng
curl http://127.0.0.1/basic.html
```

The capture ran from 08:29:02 to 08:30:33 and was saved to `/home/kali/traffic/image2.pcapng`.

## 2. Packet Inspection

The capture was filtered and inspected in Wireshark:

```
http.port == 80
```

| Frame | Description |
|---|---|
| 321–323 | TCP three-way handshake, loopback (127.0.0.1 ↔ 127.0.0.1), ports 53268 → 80 |
| 324 | `GET /basic.html HTTP/1.1` |
| 326 | `HTTP/1.1 200 OK (text/html)` |
| 328–330 | Connection torn down (FIN/ACK both directions) |

The TCP stream showed SACK, timestamps and window scaling options, consistent with a modern loopback stack; both the request and the `200 OK` response were confirmed in the packet bytes. This exercise validated that Wireshark, filters and TCP handshake analysis matched the earlier TShark work.

## 3. Secure Deletion with `shred`

A test file was created, its content and hex verified, then securely deleted:

```bash
cd HTTP_Wireshark_Assignment
mkdir shred && cd shred
echo hello > test.txt
cat test.txt
xxd test.txt
shred -vzn 3 test.txt
ls -l test.txt
xxd test.txt | head
```

| Step | Observation |
|---|---|
| Before shred | `test.txt` = 6 bytes, content `hello` |
| `shred -vzn 3` | 4 passes: random, random, random, then a final zero pass |
| After shred | File still 4096 bytes (allocation unit) but every byte is `00` |

This confirms `shred` overwrote the file's content in place before the exercise moved on to file recovery, where overwritten data should be unrecoverable.

## 4. Acquiring the DFRWS 2005 "Rhino Hunt" Evidence

The public Rhino Hunt corpus was downloaded and extracted:

```bash
mkdir rhion && cd rhion
gdown "https://drive.google.com/uc?id=1kZrWI1_hyJEgpjiuNf_iAwdpJvQLEkKS"
unzip DFRWS2005-RODEO.zip
```

| File extracted | Purpose |
|---|---|
| `RHINOUSB.dd` | 247.48 MiB raw image of the suspect USB drive |
| `rhino.log` | Primary network capture (HTTP, largest log) |
| `rhino2.log` | FTP capture (credential and file-upload traffic) |
| `rhino3.log` | Secondary FTP/HTTP capture |

Each log was hashed for the evidence record:

```bash
openssl dgst -md5 rhino.log     # c0d0093eb1664cd7b73f3a5225ae3f30
openssl dgst -md5 rhino2.log    # cd21eaf4acfb50f71ffff857d7968341
openssl dgst -md5 rhino3.log    # 7e29f9d67346df25faaf18efcd95fc30
```

## 5. USB Image Analysis (The Sleuth Kit)

The image's partition layout and file system were inspected:

```bash
fdisk -l RHINOUSB.dd
xxd -s 510 -l 2 RHINOUSB.dd
mmls RHINOUSB.dd
fsstat -o 0 RHINOUSB.dd
fls RHINOUSB.dd
```

| Property | Value |
|---|---|
| Disk size | 247.48 MiB (259,506,176 bytes, 506,848 sectors) |
| Sector 0, bytes 510–511 | `55 AA` (valid MBR boot signature) |
| File system | FAT16, volume label `mkdosfs` |
| Root directory entries | `gumbo1.txt`, `gumbo2.txt` (allocated), plus unallocated `$MBR`, `$FAT1`, `$FAT2`, `$OrphanFiles` |

Two allocated files were extracted directly with `icat` and hashed against a working copy of the image:

```bash
icat -o 0 RHINOUSB.dd 4 > gumbo1_output.txt
icat -o 0 RHINOUSB.dd 6 > gumbo2_output.txt
openssl dgst -md5 RHINOUSB.dd
dd if=RHINOUSB.dd of=RHINOUSB_My_COPY.dd
openssl dgst -md5 RHINOUSB_My_COPY.dd
```

| File | MD5 |
|---|---|
| RHINOUSB.dd | 80348c58eec4c328ef1f7709adc56a54 |
| RHINOUSB_My_COPY.dd | 80348c58eec4c328ef1f7709adc56a54 (match) |

`gumbo1_output.txt` and `gumbo2_output.txt` were recipe text files ("Shrimp and Tasso Gumbo", "Shrimp and Andouille Sausage Gumbo") — decoy content on the drive, unrelated to the case.

## 6. Recovering Deleted Files with PhotoRec

PhotoRec was run against the working copy to recover unallocated content:

```bash
photorec RHINOUSB.dd
photorec RHINOUSB_My_COPY.dd
```

Selections: whole disk → FAT16 partition → file system type "Other" (FAT/NTFS/HFS+) → "Whole" (extract from the whole partition, not just unallocated space) → destination `rhion/`.

Recovery completed with **132 files saved** to `recup_dir.2/`, mostly numbered `.txt` fragments, plus a handful of images and one Word document:

| Recovered file | Type |
|---|---|
| f0104057.jpg, f0104249.jpg, f0105065.jpg, f0105873.jpg, f0106393.jpg, f0106409.jpg, f0335081.jpg | JPEG images |
| f0106865.gif, f0106889.gif | GIF images |
| f0335017_She_died_in_February_at_the_age_of_74.doc | Word document |

## 7. Steganography Detection

The recovered JPEGs were copied into a `steg/` folder and examined with `exiftool`, then scanned with `stegdetect` (built from source after installing `automake`/`autoconf` and using `linux32 make` for 32-bit compatibility):

```bash
mkdir steg && cp recup_dir.2/*.jpg recup_dir.2/*.gif steg/
cd steg
exiftool f0104057.jpg

git clone https://github.com/poizan42/stegdetect
cd stegdetect
autoreconf -f -i
linux32 ./configure
linux32 make
./stegdetect -V
./stegdetect ../*.jpg
./stegdetect -s 3 ../*.jpg
```

| File | Default sensitivity | Sensitivity 3 |
|---|---|---|
| f0104057.jpg | negative | negative |
| f0104249.jpg | **jphide(*)** | jphide(**) |
| f0105065.jpg | skipped (false positive likely) | skipped (false positive likely) |
| f0105873.jpg | negative | jphide(*) |
| f0106393.jpg | negative | negative |
| f0106409.jpg | negative | jphide(*) |
| f0335081.jpg | negative | jphide(*) |

`f0104249.jpg` stood out as a clear positive at default sensitivity, so it became the primary target for password cracking.

## 8. Breaking the Steganography Passphrase

`rockyou.txt` was located on the system and used as the dictionary for `stegbreak`:

```bash
find / -iname "rockyou.txt*" 2>/dev/null
# /usr/share/wordlists/rockyou.txt

./stegbreak -r rules.ini -f /usr/share/wordlists/rockyou.txt ../f0104249.jpg
```

Result:

```
../f0104249.jpg : jphide[v5](gumbo)
Processed 1 files, found 1 embeddings.
Time: 8 seconds; Cracks: 131966, 16495.8 c/s
```

**The passphrase was `gumbo`** — a callback to the decoy recipe files found earlier. Running `stegbreak` across all seven JPEGs found a second embedding:

```
../f0105065.jpg : jphide[v5](gator)
../f0104249.jpg : jphide[v5](gumbo)
```

## 9. Extracting the Hidden Image

`jpseek` (Windows binary, run under Wine) was downloaded and used to extract the hidden payload from `f0104249.jpg` with the recovered passphrase `gumbo`:

```bash
wget ftp://ftp.gwdg.de/pub/linux/misc/ppdd/jphs_05.zip
unzip jphs_05.zip && unzip jphs05.zip
wine jpseek.exe f0104249.jpg r249.jpg
# Passphrase: gumbo
```

The extracted file `r249.jpg` opened as a photograph of three rhinoceroses, confirming the name of the scenario and that steganography was used to smuggle the image off the USB drive.

The `jphide`/`jpseek` Linux binaries were also installed directly via the `stego-toolkit` project for completeness:

```bash
git clone https://github.com/DominicBreuker/stego-toolkit.git
cd stego-toolkit/install
./jphide.sh
jphide      # v0.3, usage banner confirmed
jpseek      # v0.3, usage banner confirmed
```

## 10. Cracking a Password-Protected ZIP

A `contraband.zip` archive (visible earlier in the `rhion` folder, containing `rhino2.jpg`) required a password:

```bash
unzip contraband.zip
# [contraband.zip] rhino2.jpg password:

sudo apt-get install fcrackzip
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt contraband.zip
```

Result:

```
PASSWORD FOUND!!!!: pw = monkey
```

```bash
unzip contraband.zip   # password: monkey
ls -l rhino2.jpg        # 230,665 bytes
```

`rhino2.jpg` was a second rhinoceros photograph, again from the same scenario set.

## 11. Network Log Analysis — Identifying the Suspect (rhino2.log)

`rhino2.log` was opened in Wireshark to trace the FTP session where the stolen files were uploaded:

```bash
wireshark rhino2.log
```

Wireshark's built-in **Credentials** view (Tools → Credentials) surfaced the FTP login directly:

| Protocol | Username | Packet |
|---|---|---|
| FTP | gnome | 1532 (request) |

Following the FTP control stream (`tcp.stream eq 72`) showed the full login and upload sequence:

```
220 cook FTP server ready.
USER gnome
331 Password required for gnome.
PASS gnome123
230 User gnome logged in.
TYPE I
200 Type set to I.
PORT 137,30,122,253,6,124
STOR rhino3.jpg
150 Opening BINARY mode data connection for rhino3.jpg.
226 Transfer complete.
```

| Item | Value |
|---|---|
| FTP server | 137.30.120.40 (`cook`) |
| Client (attacker) | 137.30.122.253 |
| Credentials | gnome / gnome123 |
| Files uploaded | rhino1.jpg (BINARY mode), rhino3.jpg (ASCII mode — Wireshark flagged "321 bare linefeeds received in ASCII mode", risking corruption) |

The raw FTP-DATA bytes for the `STOR rhino1.jpg` transfer were inspected in the packet hex pane and matched a JPEG file header (`FF D8 FF E0 ... JFIF`), confirming genuine image data rather than an encoded payload.

## 12. Identifying the Attacker (rhino.log)

The larger `rhino.log` capture was opened to trace the attacker's web browsing and downloads:

```bash
wireshark rhino.log
```

```
http.content_type[0:5] == "image"
```

This surfaced several `200 OK (GIF89a)`/`(JPEG JFIF image)` responses from server `137.30.120.37` to client `137.30.123.234`, including `rhino5.gif` (Content-Type `image/gif`, Last-Modified Mon, 22 Mar 2004).

A `whois` lookup on the client IP identified the network it belonged to:

```bash
whois 137.30.123.234
```

| Field | Value |
|---|---|
| NetRange | 137.30.0.0 – 137.30.255.255 |
| Organization | University of New Orleans (UNO) |
| Abuse contact | hachoi@uno.edu, +1-504-280-1198 |

Following the HTTP stream that served `rhino5.gif` confirmed the filename in the GET request (`GET /~gnome/rhino5.gif HTTP/1.1`) and that it was saved locally for inspection — the GIF opened as a third rhinoceros image.

## 13. Malware Retrieved from the Same Session

The same browsing session also requested an executable:

```
GET /~gnome/rhino.exe HTTP/1.1
Host: www.cs.uno.edu
```

The HTTP response (`200 OK`, Content-Type `application/octet-stream`, Content-Length 145920) was exported from the stream as `rhino.exe`:

```bash
ls -l rhino.exe
file rhino.exe
# rhino.exe: PE32 executable for MS Windows 4.00 (console), Intel i386, 3 sections

md5sum rhino.exe
# d62d9989535c4c8db14e50b58c9f25a0
```

A public search on the MD5 hash identified this as a known Rhino Hunt artifact associated with a **Microsoft DiskPart 1.0** utility. Running it under Wine confirmed it presented itself as a legitimate DiskPart tool:

```bash
wine rhino.exe
```

```
Microsoft DiskPart version 1.0
Copyright (C) 1999-2001 Microsoft Corporation.
On computer: KALI
```

Wine also logged COM errors trying to instantiate `{4fb6bb00-3347-11d0-b40a-00aa005ff586}` (the disk management COM object), so the tool could not complete its operation in the sandboxed Wine environment — consistent with a utility designed to interact with real disk-management services on a genuine Windows host.

## Evidence Summary

| Item | Finding |
|---|---|
| Web capture | Local Apache request/response for `basic.html` captured and verified in Wireshark |
| USB image | RHINOUSB.dd, FAT16, MD5 80348c58eec4c328ef1f7709adc56a54 (imaged and re-verified) |
| Recovered files | 132 files via PhotoRec, including 7 JPEGs, 2 GIFs, 1 Word doc |
| Steganography | f0104249.jpg hid an image under passphrase `gumbo` (jphide v5); f0105065.jpg under `gator` |
| Extracted hidden image | r249.jpg — photograph of three rhinoceroses |
| Password-protected ZIP | contraband.zip, password `monkey`, contained rhino2.jpg |
| FTP credentials | gnome / gnome123, uploading rhino1.jpg and rhino3.jpg to server 137.30.120.40 from 137.30.122.253 |
| Attacker network | 137.30.123.234 / 137.30.0.0/16, registered to the University of New Orleans |
| Malware | rhino.exe, MD5 d62d9989535c4c8db14e50b58c9f25a0, PE32 console executable posing as Microsoft DiskPart |

## Key Tools Used

| Tool | Purpose |
|---|---|
| Wireshark / TShark | HTTP and FTP traffic capture and stream analysis |
| Apache2 | Local test web server |
| shred | Secure file deletion demonstration |
| gdown / wget | Evidence and tool acquisition |
| fdisk, xxd, mmls, fsstat, fls | Disk image and file system inspection (TSK) |
| icat | Direct extraction of allocated files by inode |
| PhotoRec | File carving from unallocated/whole-partition space |
| exiftool | Image metadata inspection |
| stegdetect / stegbreak | Steganography detection and dictionary password cracking |
| jphide / jpseek | Steganographic embedding and extraction (via Wine) |
| fcrackzip | ZIP password cracking |
| whois | Attribution of the attacker's IP range |
| Wine | Running Windows binaries (jpseek.exe, rhino.exe) in Linux |
| openssl dgst / md5sum | Evidence hashing |

## Forensic Notes

- Every image of RHINOUSB.dd and every log file was hashed before analysis began, and the working copy of the disk image was independently re-hashed and matched.
- File recovery used PhotoRec's "Whole partition" mode rather than "unallocated space only," so recovered files may include both deleted and still-allocated content; `icat` was used separately for the two intact FAT16 directory entries.
- The steganography passphrases (`gumbo`, `gator`) were both found via dictionary attack against `rockyou.txt`, not guessed — this is a lab exercise using a widely-available public password list, not a general-purpose password-recovery technique.
- The `rhino.exe` MD5 was checked against public references rather than analyzed by static/dynamic reverse engineering; running it in Wine is not equivalent to full malware analysis and was done only for identification, inside an isolated lab VM.
- Attribution to the University of New Orleans network is based solely on a `whois` lookup of an IP address range from a 2004 training capture and should not be read as identifying any individual.
- All USB image, network log and executable artifacts analyzed here are from the publicly published **DFRWS 2005 "Rhino Hunt" (Forensic Rodeo)** training scenario, not live evidence.
