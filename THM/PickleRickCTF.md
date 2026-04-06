
# Pickle Rick CTF — Writeup

## Enumeration

First thing is first, we want to get more information on the webpage, so we go through the enumeration stage.

### Nmap Scan

We run an Nmap scan on the target IP address:

```bash
nmap 10.145.184.70 -A -T5 -oN scan
```

> Timing set to T5 since this is a CTF — no need to be discrete. Output saved to `scan`.

**Results:**
- **Port 22** — SSH running OpenSSH 7.2p2. Possible attack vector if credentials are found.
- **Port 80** — HTTP running Apache 2.4.18. Potential for web application exploitation, file upload, or reverse shell.

---

## Web Application Analysis

Navigating to the site in a browser, we find that Rick does not remember his password — so the goal is likely to find his login credentials.

**Inspecting the page source** reveals his username:

```
R1ckRul3s
```

However, we run into some problems:
- There is no visible login field on the page.
- FTP connection attempts fail.

We need to look further.

---

## Directory Brute Forcing

We use `dirb` with the dirbuster wordlist to enumerate hidden files and directories:

```bash
dirb http://10.145.184.70 /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -X .php,.html,.css,.js,.txt,.pdf
```

**Discovered:**
- `login.php`
- `portal.php`
- `robots.txt`

---

## Gaining Access

Navigating to `robots.txt` reveals the password:

```
Wubbalubbadubdub
```

We log in at `login.php`, which redirects us to a **command panel**.

---

## Flag 1

Running `ls -a` in the command panel reveals a suspicious file:

```
Sup3rS3cretPickl3Ingred.txt
```

`cat` is blocked, but after some trial and error, `tac` works:

```bash
tac Sup3rS3cretPickl3Ingred.txt
```

**First ingredient:** `mr. meeseek hair`

---

## Flag 2

Reading `clue.txt` (also via `tac`) hints at looking around the file system.

Running `ls -al` in the `/home/` directory reveals a `rick` home directory. Listing its contents exposes a file called `second ingredients`:

```bash
tac /home/rick/second\ ingrediants
```

**Second ingredient:** *(contents of the file)*

---

## Flag 3

We attempt to list the root directory using sudo:

```bash
sudo ls -al /root/
```

It works. We find `3rd.txt` listed. We read it:

```bash
sudo tac /root/3rd.txt
```

**Third ingredient:** *(contents of the file)*
