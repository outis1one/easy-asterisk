# Easy Asterisk - Simple Intercom & VoIP System

A bash-based installer and management system for Asterisk PBX with Baresip client, designed for personal use in home labs, DIY projects, and intercom systems.

**Version:** 0.9.8  
**License:** MIT (see below)  
**Author:** [Your Name/Organization]

---

## ⚠️ IMPORTANT DISCLAIMER

**THIS SCRIPT IS FOR PERSONAL/HOME LAB USE ONLY**

This project was created for personal intercom systems in home lab environments. While Asterisk itself is enterprise-grade software used in corporate environments, **this installation script and configuration has NOT been tested for business/commercial use**.

- ✅ **Intended use:** Home labs, personal projects, DIY intercoms, learning VoIP
- ❌ **Not intended for:** Business phone systems, commercial deployments, mission-critical communications

**USE ENTIRELY AT YOUR OWN RISK:**
- The author(s) assume **NO liability** for any issues, damages, or problems
- No warranty or guarantee of any kind is provided
- Test thoroughly before relying on this for anything important
- You are solely responsible for your deployment and any consequences
- Not suitable for emergency services (911/112) or critical communications

**Corporate/Business Users:** Asterisk is proven enterprise software, but this particular script and its configuration approach has not been validated for business environments. It may work great, it may fail completely—we simply don't know without extensive testing. Proceed with caution and thorough testing if considering business use.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Current Limitations](#current-limitations)
- [Connection Modes Explained](#connection-modes-explained)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Dynamic IP Handling](#dynamic-ip-handling)
- [Network Architecture](#network-architecture)
- [Client Applications](#client-applications)
- [Troubleshooting](#troubleshooting)
- [License & Attributions](#license--attributions)

---

## Overview

Easy Asterisk simplifies the deployment of VoIP systems for personal use:
- 🔊 **Auto-answer intercoms** - Door stations, room-to-room communication
- 📞 **Home phone system** - Call between rooms, devices, or family members
- 🏢 **Multi-location home labs** - Connect multiple sites via VPN
- 📢 **Page/intercom groups** - Whole-house announcements

**Think of it as:** Your own private intercom system for your home or home lab. Call from room to room, page the whole house, or connect remote locations over VPN.

**Original use case:** I needed a way for kiosk computers to act as intercoms in my home lab. No complicated setup, just something that works.

---

## Features

### Server Management
- ✅ Interactive menu-driven installer (no command-line wizardry needed)
- ✅ Category-based device organization (Kiosks, Mobile Phones, Custom)
- ✅ Auto-answer and ring modes per device
- ✅ Group calling (call multiple devices at once, or page everyone)
- ✅ Device import/export for backup and migration
- ✅ Network diagnostics and connection testing

### Network Flexibility
- ✅ **LAN/VPN Mode**: Works on your local network or VPN with minimal setup
- ✅ **FQDN Mode**: Internet calling with encryption (requires domain name)
- ✅ Automatic NAT/VLAN traversal (works across network segments)
- ⚠️ **Dynamic IP support**: Server handles IP changes, but FQDN requires additional setup (see [Dynamic IP Handling](#dynamic-ip-handling))

### Client Features
- ✅ Push-to-talk (PTT) button support (foot pedal or USB button)
- ✅ Auto-answer for hands-free operation (perfect for intercoms)
- ✅ Audio ducking (pauses music during calls)
- ✅ Systemd service management (starts automatically on boot)
- ✅ Auto-reconnect on network changes
- ✅ **Voice calls only** (audio only)

---

## Current Limitations

**What this script does NOT currently support:**

- ❌ **Video calling** - Audio only. Video requires significantly more bandwidth and processing power. Most home networks and hardware aren't suited for reliable multi-party video.
- ❌ **Text messaging** - Not implemented (though Asterisk supports it, this script doesn't configure it)
- ❌ **File attachments** - Not supported
- ❌ **Voicemail** - Not configured by this script
- ❌ **Call recording** - Not configured by this script
- ❌ **Emergency services** - Do NOT use this for 911/112 calls

**These are audio-only voice intercoms and phone calls.** Think traditional phone system, not modern messaging apps.

**Why no video?**
- Requires 10-100x more bandwidth than audio
- Needs significantly more CPU power on server and clients  
- Most home networks struggle with multiple HD video streams
- More complex NAT traversal issues
- Not the original goal of this project (simple intercoms)

---

## Connection Modes Explained

Easy Asterisk supports two ways to connect devices.

### 🏠 LAN/VPN Mode - "The Easy Button"

**What it means in plain English:**
Everything stays on your local network or VPN. Private and simple.

**Best for:**
- Home intercom systems
- Home lab setups
- Multiple locations connected by VPN

**Why it's easier:**
- ✅ **No domain name needed** - Just use your server's IP address (like 192.168.1.100)
- ✅ **No SSL certificates needed** - No cryptic certificate errors
- ✅ **No router configuration** - No port forwarding headaches
- ✅ **Works across VLANs** - Even if your network has separate segments
- ✅ **Perfect for private systems** - Nothing exposed to the internet

**VPN Options (if you have multiple locations):**

If you want to connect multiple sites (home + workshop, home + parents' house, etc.):

- **[Tailscale](https://tailscale.com/)** ⭐ *Recommended for beginners*
  - Install it, click connect, you're done
  - Free for personal use (up to 100 devices)
  - Works like magic - no router configuration
  - Cloud-managed (they run the coordination server)
  
- **[Netbird](https://netbird.io/)** - Alternative to Tailscale
  - Open-source, can be self-hosted but doesn't have to be
  - Free cloud-managed option available
  - Similar ease of use
  
- **WireGuard** - For tech-savvy users who want full control
- **OpenVPN** - Traditional VPN, well-tested

**Setup time:** 5 minutes  
**Difficulty:** ⭐ Easy

### 🌐 FQDN Mode - "The Internet Setup"

**What it means in plain English:**
Connect from anywhere with WiFi or cell data using a proper domain name (like `pbx.yourhouse.com`) and encrypted connections.

**Best for:**
- Calling from anywhere with WiFi/cell connection (no VPN needed)
- When you want encryption
- Learning about DNS, certificates, and VoIP

**What you need:**
- ✅ **Domain name** - Like `pbx.yourhouse.com` (costs ~$10-15/year)
- ✅ **SSL/TLS certificates** - Free with Let's Encrypt (script helps with this)
- ✅ **Port forwarding on router** - Opening specific "doors" in your firewall
- ✅ **Static IP or Dynamic DNS** - See [Dynamic IP Handling](#dynamic-ip-handling)

**Why it's worth the effort:**
- ✅ **TLS encryption** - All call setup is encrypted
- ✅ **SRTP encryption** - All audio is encrypted
- ✅ **Call from anywhere with WiFi** - Coffee shop, vacation, friend's house
- ✅ **No VPN needed** - Just connect directly

**The Caddy Shortcut:**

If you're already running [Caddy](https://caddyserver.com/) (a reverse proxy that auto-manages SSL certificates) in Docker, this becomes **much easier**. Caddy automatically gets and renews Let's Encrypt certificates.

**Good Caddy/Docker guide:** Check out [DoTheEvo's selfhosted-apps-docker](https://github.com/DoTheEvo/selfhosted-apps-docker) for setting up Caddy. Once Caddy is running with your domain, Easy Asterisk can auto-sync the certificates.

**Setup time:** 30-60 minutes (first time)  
**Difficulty:** ⭐⭐⭐ Intermediate

### 🤔 Which Mode Should I Use?

**Choose LAN/VPN if:**
- You're setting up a home intercom system
- All devices are on the same network (or connected via VPN)
- You want "set it and forget it" simplicity
- You don't want to expose anything to the internet

**Choose FQDN if:**
- You need to call from anywhere with WiFi/cell data (hotels, coffee shops, etc.)
- You can't or don't want to use VPN
- You want to learn about DNS, certificates, and internet-facing VoIP
- You're comfortable with port forwarding and Dynamic DNS

**Pro tip:** Start with LAN/VPN mode. Get it working. *Then* add FQDN if you need it. You can run both modes simultaneously!

---

## Requirements

### Server Requirements
- **OS**: Ubuntu 22.04/24.04 LTS or Debian 11/12
- **RAM**: 512MB minimum, 1GB recommended
- **CPU**: 1 core minimum, 2+ cores for >10 concurrent calls
- **Disk**: 2GB minimum
- **Network**: Static local IP recommended (so the server address doesn't change)

**Translation:** Any old computer from the last 10 years will work. Even a Raspberry Pi 4 works great for home use.

### Client Requirements
- **OS**: Ubuntu/Debian with desktop environment (for built-in Baresip client)
- **Audio**: Working speakers and microphone
- **Optional**: USB button or foot pedal for push-to-talk

**For mobile phones and other devices:** See [Client Applications](#client-applications) section.

### Network Requirements (FQDN Mode Only)

If you're using FQDN mode, you need to forward these ports on your router:

| Port Range | Protocol | What It Does |
|------------|----------|--------------|
| 5060 | UDP | Phone registration (unencrypted) |
| 5061 | TCP | Phone registration (encrypted) |
| 10000-20000 | UDP | Actual voice audio |

**Translation:** Think of ports like channels on a walkie-talkie. You need to tell your router "when someone knocks on port 5061, send them to the Asterisk server."

---

## Quick Start

### 1. Install Server

```bash
# Download the installer
wget https://example.com/easy-asterisk-v0.9.8.sh
chmod +x easy-asterisk-v0.9.8.sh

# Run it (you'll see a menu)
sudo ./easy-asterisk-v0.9.8.sh

# Select: Install/Configure > Server only (or Full)
```

**What happens:** The script installs Asterisk (the phone system software), sets up basic configuration, and creates the management menus.

### 2. Choose Your Connection Mode

**For LAN/VPN (Easy - Recommended First):**
- During install, just press Enter when asked about internet setup
- Server listens on your local network only
- Write down the server's IP address (it'll show you)
- Done! Skip to step 3.

**For FQDN (Internet Calling):**
- After install, go to: **Server Settings > Setup Internet Access**
- Choose certificate source:
  - **Auto-Sync from Caddy** - If you have Caddy running (easiest)
  - **Standalone Certbot** - Let the script get certificates (requires port 80 open)
  - **Self-Signed** - For testing only (browsers/apps will complain)
  - **Manual Path** - If you already have certificates
- Enter your domain name (like `pbx.yourhouse.com`)
- Set up port forwarding on your router (script shows you what to forward)
- **If you have a residential ISP:** See [Dynamic IP Handling](#dynamic-ip-handling) below!

### 3. Add Your First Device

```bash
# Run the script again
sudo ./easy-asterisk-v0.9.8.sh

# Navigate to: Device Management > Add device
# 
# You'll be asked:
# - Category: Choose "Kiosks" for auto-answer intercoms, "Mobile" for phones
# - Extension: Pick a number (101, 102, 201, etc.)
# - Name: Something descriptive like "Front Door" or "Kitchen Tablet"
# - Connection type: 
#   - LAN/VPN if you're on local network
#   - FQDN if you're using your domain name
```

**The script will show you:**
```
═══════════════════════════════════════════════════════
  DEVICE ADDED
═══════════════════════════════════════════════════════
  Client Configuration:
  Server:     192.168.1.100  (or pbx.yourhouse.com)
  Port:       5060  (or 5061 for FQDN)
  Transport:  UDP  (or TLS for FQDN)
  Extension:  101
  Password:   abc123xyz789
  Encryption: None  (or SRTP for FQDN)
═══════════════════════════════════════════════════════
```

**Write this down!** You'll need it to configure your phone apps.

### 4. Install Desktop Client (Optional)

If you want a computer to act as an auto-answer intercom:

```bash
# On the client computer
sudo ./easy-asterisk-v0.9.8.sh

# Select: Install/Configure > Client only
# Enter the server info from step 3
# Choose auto-answer or manual ring mode
```

**What this does:** Installs Baresip (a lightweight SIP client), configures it to connect to your server, and sets it to start automatically on boot.

### 5. Configure a Mobile Phone App

See [Client Applications](#client-applications) section below.

---

## Dynamic IP Handling

**If you have a residential ISP, you probably have a dynamic IP address.** This means your public IP can change at any time (power outage, modem restart, ISP maintenance), which breaks FQDN mode.

### The Problem

Your domain name (`pbx.yourhouse.com`) points to an IP address. When your ISP changes your IP, the domain still points to the old (wrong) address, and nothing works.

### The Solution: Dynamic DNS (DDNS)

You need something that automatically updates your domain's DNS record when your IP changes.

#### Option 1: DDClient (Recommended)

**[DDClient](https://ddclient.net/)** is a tool that monitors your IP and updates DNS providers automatically.

**If you're already using Docker**, DoTheEvo has a great guide and suggests the [ddclient-docker](https://github.com/DoTheEvo/selfhosted-apps-docker/tree/master/ddclient) container.

**Quick setup:**
```bash
# Install ddclient
sudo apt install ddclient

# Configure for your DNS provider (Cloudflare, Namecheap, etc.)
sudo nano /etc/ddclient.conf

# Enable and start
sudo systemctl enable ddclient
sudo systemctl start ddclient
```

**Popular DNS providers with DDNS support:**
- Cloudflare (free)
- DuckDNS (free, very simple)
- No-IP (free tier available)
- Dynu (free)
- Your domain registrar (Namecheap, GoDaddy, etc. often support it)

#### Option 2: Router-Based DDNS

Many routers have built-in DDNS clients. Check your router settings for "Dynamic DNS" or "DDNS". Configure it with your DNS provider credentials, and it'll handle updates automatically.

#### Option 3: Custom Script

There are many scripts available that check your IP and update DNS:

**Simple curl-based checker:**
```bash
#!/bin/bash
# Save as /usr/local/bin/update-ip.sh

CURRENT_IP=$(curl -s ifconfig.me)
STORED_IP=$(cat /tmp/last_ip 2>/dev/null)

if [ "$CURRENT_IP" != "$STORED_IP" ]; then
    echo $CURRENT_IP > /tmp/last_ip
    # Add your DNS update command here (Cloudflare API, etc.)
    # curl -X PUT "https://api.cloudflare.com/client/v4/zones/..."
    logger "IP changed to $CURRENT_IP"
fi
```

**Run it every 5 minutes with cron:**
```bash
*/5 * * * * /usr/local/bin/update-ip.sh
```

### Built-In IP Update (Limited)

Easy Asterisk includes a basic IP update mechanism for the server side (updates Asterisk's NAT settings), but this **does NOT update your DNS**. You still need DDNS for that.

The built-in updater helps Asterisk adapt to IP changes, but clients won't be able to find your server unless your domain's DNS is also updated.

---

## Network Architecture

### Simple LAN Setup (One House)

```
┌─────────────┐         ┌─────────────┐
│  Door Kiosk │         │   Kitchen   │
│  (Ext 101)  │         │  (Ext 102)  │
└──────┬──────┘         └──────┬──────┘
       │                       │
       └───────┬───────────────┘
               │
        ┌──────▼──────┐
        │   Asterisk  │
        │   Server    │
        │ 192.168.1.5 │
        └─────────────┘
               │
        ┌──────▼──────┐
        │    Phone    │
        │  (Ext 201)  │
        └─────────────┘
```

**How it works:** Everyone connects to the server's local IP. When you dial 101, the door kiosk answers automatically. When you dial 102, the kitchen tablet rings.

### VPN Setup (Multiple Locations)

```
Home                                 Workshop
┌─────────────┐                     ┌─────────────┐
│   Bedroom   │                     │    Tool     │
│  (Ext 101)  │                     │    Area     │
└──────┬──────┘                     │  (Ext 201)  │
       │                             └──────┬──────┘
┌──────▼──────┐                     ┌──────▼──────┐
│  Tailscale  │◄───────────────────►│  Tailscale  │
│   Router    │   (VPN Magic)       │   Router    │
└──────┬──────┘                     └─────────────┘
       │
┌──────▼──────┐
│   Asterisk  │
│   Server    │
│100.64.1.5   │ <- Tailscale IP
└─────────────┘
```

**How it works:** Tailscale creates a virtual network. Both locations appear to be on the same local network, even though they might be miles apart. Works exactly like the LAN setup.

### FQDN Setup (Internet Calling)

```
┌─────────────┐                          ┌─────────────┐
│   Away      │                          │    Home     │
│   Phone     │                          │   Tablet    │
│ (WiFi/Cell) │                          │  (Ext 201)  │
└──────┬──────┘                          └──────┬──────┘
       │                                        │
       │           The Internet                 │
       │                                        │
       └────────┬──────────────────────┬────────┘
                │                      │
         ┌──────▼──────┐        ┌──────▼──────┐
         │   Router    │        │   Asterisk  │
         │ (Ports Fwd) │───────►│   Server    │
         │   + DDNS    │        │ TLS Enabled │
         └─────────────┘        └─────────────┘
           Your Router            pbx.yourhouse.com
```

**How it works:** Your domain name (pbx.yourhouse.com) points to your router. DDNS keeps the IP updated. The router forwards specific ports to your Asterisk server. All connections are encrypted with TLS/SRTP.

---

## Client Applications

### Desktop/Kiosk (Included with Script)

**Baresip** - Installed automatically by Easy Asterisk
- Perfect for auto-answer intercoms
- Low CPU usage (works on old PCs)
- Push-to-talk button support
- Starts automatically on boot
- **Audio only** (no video)

**Use for:** Fixed kiosks, door stations, dedicated intercom terminals, old computers repurposed as intercoms

### Mobile & Desktop Apps (You Install These)

For phones, tablets, Windows, Mac, etc., you need to install a SIP client app separately.

#### Linphone ⭐ Recommended

**What it is:** Free, open-source phone app that works on everything

- **Platforms**: Windows, macOS, Linux, iPhone, Android
- **License**: GPL-3.0 (Free)
- **Download**: https://www.linphone.org/
- **Voice calls only** (video won't work with this Asterisk setup)

**How to set it up:**

1. Download and install Linphone from their website
2. Open Linphone
3. **Configure encryption (FQDN mode only)**:
   - Go to Settings → Advanced Settings → Calls
   - Set **Media encryption** to **SRTP**
   - Close settings
4. Add your account:
   - Go to Settings → Accounts → Add account
   - Choose "Use SIP account"
5. Enter the info from when you added the device:

**For LAN/VPN:**
```
Username: 201
Password: [from Easy Asterisk]
Domain: 192.168.1.100  (your server's IP)
Transport: UDP
Port: 5060
```

**For FQDN:**
```
Username: 201
Password: [from Easy Asterisk]
Domain: pbx.yourhouse.com
Transport: TLS
Port: 5061
Enable encryption (SRTP): Yes
```

6. Save and test by calling another extension!

**Note:** Linphone supports video calling, but this Asterisk setup is audio-only. Video features in the app won't work with Easy Asterisk.

---

## Troubleshooting

### "I can't hear anything" (Audio Issues)

**Check if microphone is muted:**
```bash
# Check status
pactl get-source-mute @DEFAULT_SOURCE@

# If it says "yes", unmute it:
pactl set-source-mute @DEFAULT_SOURCE@ 0
```

**Check if audio system is running:**
```bash
systemctl --user status pipewire pipewire-pulse
```

If you see red "failed" text, restart it:
```bash
systemctl --user restart pipewire pipewire-pulse
```

**Still no audio?** 
- Try logging out and back in
- Check if your speakers/headphones are plugged in
- Run the built-in diagnostics: **Tools > Verify Audio/Codec Setup**

### "My phone won't connect" (Connection Issues)

**For LAN/VPN Mode:**

Test if you can reach the server:
```bash
ping [server-ip]
```

If that works, test the SIP port:
```bash
# From another computer on the network
nc -u -v [server-ip] 5060
```

**For FQDN Mode:**

Test if your domain works:
```bash
ping pbx.yourhouse.com
```

Test if TLS is working:
```bash
openssl s_client -connect pbx.yourhouse.com:5061
```

If you see certificate errors, your SSL setup isn't right. Re-run: **Server Settings > Setup Internet Access**

**Check port forwarding:**

From a device OUTSIDE your network (use your phone's cellular):
```bash
nc -v pbx.yourhouse.com 5061
```

If this fails, your port forwarding isn't set up correctly on your router.

### "Mobile devices on VPN can't reach Asterisk" (VPN Issues)

When mobile devices connect through a VPN (Tailscale, WireGuard, etc.), Asterisk needs to know about the VPN subnet. Without this, VPN-connected devices appear offline.

**Fix:**

1. Run the installer: `sudo ./easy-asterisk-v0.10.0.sh`
2. Go to: **Server Settings > Configure VLAN/VPN Subnets**
3. Answer "y" when asked about VLANs/VPNs
4. Add your VPN subnet(s):
   - **Tailscale**: `100.64.0.0/10`
   - **WireGuard**: Usually `10.x.x.x/24` (check your WireGuard config)
   - **OpenVPN**: Check your VPN config for the tunnel subnet
5. The script will auto-detect VPN interfaces on the server and suggest subnets

**Important:** The Asterisk server itself must also be on the VPN. If using Tailscale, install Tailscale on the server too. Mobile devices should connect to the server's **VPN IP** (e.g., `100.x.x.x` for Tailscale), not its LAN IP.

**Verify VPN connectivity:**
```bash
# On the mobile device (or from another VPN device), ping the server's VPN IP
ping 100.x.x.x

# Test SIP port through VPN
nc -u -v 100.x.x.x 5060
```

### "One-way audio when switching from WiFi to mobile data"

This is a known issue with SIP clients on mobile devices. When the phone switches networks (WiFi to cellular or vice versa), the phone's IP address changes but the active audio stream may not update properly.

**What happens:**
- The phone switches to mobile data and gets a new IP
- SIP signaling may update, but the audio (RTP) stream still uses the old path
- Result: the caller can't be heard by the receiving person

**Server-side fixes (already applied for mobile devices in v0.10.0):**
- `rtp_symmetric=yes` - Asterisk sends audio back to wherever it receives audio from
- `rtp_keepalive=15` - Asterisk sends periodic keepalive packets to maintain NAT mappings
- `rtp_timeout=120` - Detects dead audio streams after 120 seconds
- `qualify_frequency=30` - Checks device availability every 30 seconds

**Client-side fixes (on your phone):**

For **Sipnetic**:
- Settings > Network > Enable "ICE" (if available)
- Settings > Network > Enable "STUN" (if available)
- Settings > Network > Keep-alive interval: 15-30 seconds
- Make sure "Background mode" is enabled

For **Linphone**:
- Settings > Network > Enable ICE
- Settings > Network > STUN server: `stun.l.google.com:19302`
- Settings > Network > Enable TURN (if behind strict NAT)

For **any SIP app**:
- Disable WiFi sleep / battery optimization for the app
- Enable "Keep WiFi on during sleep" in Android settings
- After switching networks, hang up and redial - this forces a clean reconnection

**If the problem persists:**
- Consider using FQDN mode with TLS/SRTP instead of LAN/VPN mode
- FQDN mode enables ICE (Interactive Connectivity Establishment) which handles network changes better
- Alternatively, keep your phone on one network type (WiFi or mobile data) during calls

### "My IP changed and FQDN stopped working"

See [Dynamic IP Handling](#dynamic-ip-handling) section. You need to set up DDNS.

### "My push-to-talk button doesn't work"

**Check permissions:**
```bash
# See if your user is in the 'input' group
groups [username]
```

If you don't see "input" in the list, the script should have added it. Try logging out and back in—Linux needs you to re-login for group changes to take effect.

**Check the PTT service:**
```bash
journalctl -t kiosk-ptt -f
```

Press your button. You should see messages like:
```
PTT pressed - mic unmuted
PTT released - mic muted
```

If you see "Permission denied", log out and back in.

### Use the Built-in Diagnostics

Easy Asterisk has diagnostic tools built in:

- **Server Settings > Test SIP connectivity** - Checks if Asterisk is running and listening
- **Server Settings > Router Doctor** - Tests if traffic is reaching the server
- **Client Settings > Run Diagnostics** - Comprehensive client health check
- **Tools > Verify Audio/Codec Setup** - Checks audio configuration

**When in doubt, run the diagnostics first.**

---

## License & Attributions

### Easy Asterisk Script

```
MIT License

Copyright (c) 2024 [Your Name/Organization]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**What this means in plain English:** 

You can use this script for anything (personal or commercial). You can modify it, share it, whatever. Just keep the copyright notice. 

**BUT:** If something breaks, that's on you. This comes with zero warranty. The author(s) are not responsible for anything that happens when you use this script. Not legally, not morally, not in any way. You use this entirely at your own risk.

### Third-Party Software

This script installs and configures the following open-source software:

#### Asterisk PBX

- **License**: GPL-2.0
- **Copyright**: Sangoma Technologies Corporation
- **Website**: https://www.asterisk.org/
- **Source**: https://github.com/asterisk/asterisk
- **What it does**: The actual phone system (PBX) that routes calls

**Important:** Asterisk is GPL-2.0 licensed. This script doesn't bundle Asterisk—it downloads it from Ubuntu/Debian repositories. If you modify and redistribute Asterisk itself (not this script), you must follow GPL-2.0 terms.

#### Baresip

- **License**: BSD-3-Clause
- **Copyright**: Alfred E. Heggestad and Contributors
- **Website**: https://github.com/baresip/baresip
- **What it does**: Lightweight SIP client for desktop/kiosk installations

**Important:** BSD license is very permissive. You can do almost anything with it. Attribution is appreciated but not required.

### Client Applications (Not Included)

SIP client apps like Linphone are separate applications with their own licenses. Users download them independently—they are not distributed with this script, so their licenses don't apply to Easy Asterisk.

### No Warranty / Use At Your Own Risk

**THIS BEARS REPEATING:**

- ❌ No warranty of any kind
- ❌ No guarantee it will work for your use case
- ❌ No liability for damages, problems, or issues
- ❌ Not suitable for critical communications
- ❌ Not suitable for emergency services
- ❌ Author(s) assume ZERO responsibility for anything

**Test it. Break it. Learn from it. But don't blame anyone if something goes wrong.**

---

## Contributing

Want to make Easy Asterisk better? Cool!

**How to contribute:**

1. Fork the repository
2. Make your changes
3. Test on Ubuntu 22.04 or 24.04
4. Submit a pull request

**Guidelines:**

- Follow existing code style
- Comment your code
- Update this README if you add features
- Test thoroughly

**Areas that need help:**

- 📱 Better mobile client guides
- 🐳 Docker container version
- 🎨 Web interface for management
- 💬 Text messaging support
- 📎 File attachment support
- 🌍 Internationalization (translations)

---

## Changelog

### v0.9.8 (Current)
- ✨ Added client export/import functionality
- ✨ Added device rename feature
- ✨ Added category and room rename features
- ✨ Improved device listing with category filtering
- 🐛 Fixed category display names in device list
- 🐛 Fixed device parsing with proper whitespace handling
- 🔒 Added backup protection before configuration changes

### v0.9.5
- 🐛 Fixed Stasis startup issues
- ✨ Added automatic VLAN/NAT traversal
- ✨ Added per-device connection type selection
- ⚡ Improved transport-level NAT configuration

### v0.9.0
- 🎉 Initial public release
- ⚙️ Basic server and client installation
- 📂 Category and room management
- 🎙️ PTT support

---

## Roadmap

**Things that might happen someday:**

- [ ] 💬 Text messaging support
- [ ] 📎 File attachment support
- [ ] 🌐 Web-based management interface
- [ ] 📼 Call recording
- [ ] 📧 Voicemail system
- [ ] 🐳 Docker container deployment
- [ ] 📜 Ansible playbook version
- [ ] 🗺️ Integration with home automation (Home Assistant, etc.)

**Video calling:** Not currently planned. Requires significantly more bandwidth and processing power. Most home labs and networks aren't suited for reliable video conferencing. There are better solutions for video (Jitsi, Zoom, etc.).

---

## Support & Community

- 📖 **Documentation**: You're reading it!
- 🐛 **Bug Reports**: [Your GitHub Issues URL]
- 💬 **Discussions**: [Your Forum/Discord/IRC]
- 📧 **Email**: [Your Contact Email]

**Before asking for help:**
1. Run the built-in diagnostics
2. Check the Troubleshooting section above
3. Search existing GitHub issues
4. Include error messages and relevant logs

**Remember:** This is a personal project. Support is best-effort and community-driven.

---

## FAQ

**Q: Is this really free?**  
A: Yes. MIT licensed. Use it however you want.

**Q: Will this work on Raspberry Pi?**  
A: Yes! Raspberry Pi 4 works great. Pi 3 works for small setups (<5 devices).

**Q: Can I use this for my business?**  
A: This script is designed for personal/home lab use. Asterisk itself is used in businesses, but this particular installation script hasn't been tested for commercial deployments. Use at your own risk.

**Q: Do I need to know Linux?**  
A: Basic knowledge helps. If you can copy/paste commands and follow instructions, you can probably do this.

**Q: What about Windows/Mac clients?**  
A: Install Linphone or another SIP client. Works great on Windows and Mac.

**Q: Why no video calling?**  
A: Bandwidth and processing requirements. Video needs 10-100x more resources than audio. This project focuses on simple, reliable audio intercoms.

**Q: Can I send text messages?**  
A: Not currently. Asterisk supports it, but this script doesn't configure messaging yet. Maybe in a future version.

**Q: Is it secure?**  
A: FQDN mode uses TLS/SRTP encryption. LAN/VPN mode is as secure as your local network. Don't expose LAN mode directly to the internet without VPN.
**Q: My ISP changes my IP address, will FQDN mode break?**
A: Yes, unless you set up Dynamic DNS (DDNS). See the Dynamic IP Handling section.
**Q: Can I get support?**
A: Community support through GitHub. This is a personal project—no paid support available.
**Q: Why did you make this?**
A: I needed a simple intercom system for my home lab kiosks and couldn't find anything that wasn't either overcomplicated or expensive. So I made this.
**Q: Will this work for [specific use case]?**
A: Try it and find out! It's designed for home lab intercoms, but Asterisk is flexible. Just remember: use at your own risk, no warranties.

**Made with ❤️ for home labbers and DIY enthusiasts**
*"Because sometimes you just need to yell at the other room without getting up."*
