# Kali setup for the CTF

You said you have burner laptops with admin rights and enough RAM to run a VM.
Here is a sensible, low-drama setup. Do this **before** the event.

## 1. Run Kali in a VM, not on bare metal

A VM gives you snapshots (roll back if you break something), isolation, and a clean
image you can copy to every teammate. On your host OS:

1. Install **VirtualBox** (free) or **VMware Workstation Player** (free for personal use).
2. Download the **Kali Linux VirtualBox/VMware image** (pre-built) from
   https://www.kali.org/get-kali/#kali-virtual-machines — this avoids a full OS install.
3. Import it, give it **4 vCPU / 8 GB RAM** if you can spare it, and a 40–60 GB disk.
4. Boot, log in (default user `kali` / password `kali`), then:

```bash
sudo apt update && sudo apt -y full-upgrade
```

5. **Take a snapshot** now and call it `clean`. Take another after step 3 below (`ready`).

> Tip: the default Kali image ships with most tools. If you install the lighter
> `kali-linux-core`, add the toolkit with `sudo apt install -y kali-linux-default`.

## 2. Keep the VM networking safe

For solving these offline challenges you do not need internet in the VM at all.
Use **NAT** (default) if you want to `apt install` things, and switch to **Host-only**
or disable the adapter when you want a sealed analysis box (important for the malware
triage challenges — never let unknown code reach the network).

## 3. Install the tools these challenges use

Most are already on Kali. This one line covers the gaps:

```bash
sudo apt update && sudo apt install -y \
  wireshark tshark tcpdump nmap \
  binwalk foremost exiftool steghide zsteg \
  john hashcat hashcat-utils fcrackzip \
  yara jq xxd ripgrep \
  python3-pip python3-venv git curl
```

A couple need a note:

- **pyModeS** (ADS-B decoding) is a Python package. Use a virtual environment so you
  don't fight Kali's system Python:
  ```bash
  python3 -m venv ~/ctfenv
  source ~/ctfenv/bin/activate
  pip install pyModeS
  ```
  Remember to `source ~/ctfenv/bin/activate` in any terminal where you decode ADS-B.

- **CyberChef** — the browser "Swiss army knife" for decoding. Install the offline copy:
  ```bash
  sudo apt install -y cyberchef      # then open /usr/share/cyberchef/index.html
  ```
  Or just bookmark https://gchq.github.io/CyberChef/.

- **Wireshark as non-root**: when prompted during install, allow non-superusers to
  capture. If you skipped it:
  ```bash
  sudo dpkg-reconfigure wireshark-common   # answer "Yes"
  sudo usermod -aG wireshark $USER          # then log out and back in
  ```

## 4. Get the challenge files into the VM

Easiest: copy `challenges/avians-ctf-pack.zip` into the VM (shared folder, or just
download it from your running portal) and unzip:

```bash
unzip avians-ctf-pack.zip -d avians-ctf
cd avians-ctf
```

Then run the portal from the repo root so you can download files and submit flags:

```bash
python3 -m http.server 8000     # open http://localhost:8000/portal/
```

## 5. A tiny cheat sheet to tape next to the laptop

| You have… | Reach for… |
|---|---|
| An unknown file | `file`, `xxd`, `strings`, `binwalk`, `exiftool` |
| A `.pcap` | Wireshark (`tshark` for scripting), Follow TCP Stream, Export Objects |
| A text log | `grep`, `awk`, `sort`, `uniq -c`, `less`; JSON logs → `jq` |
| Base64 / hex / ROT13 | `base64 -d`, `xxd -r -p`, `tr`, or CyberChef "Magic" |
| A password-protected ZIP / hashes | `zip2john` → `john`, or `hashcat` + the aviation wordlist |
| Hidden data in an image | `binwalk`, `steghide`, `zsteg`, `strings` |
| Raw ADS-B / Mode S hex | `pyModeS` |
| "Is this sample malware?" | `strings`, `yara`, read it, never run it |

## 6. Share one image with the whole team

Once your VM is set up and snapshotted, **export it** (VirtualBox: File → Export Appliance
→ `.ova`) and give the `.ova` to your three teammates. Everyone starts from the same
known-good box, which saves a lot of event-day pain.
