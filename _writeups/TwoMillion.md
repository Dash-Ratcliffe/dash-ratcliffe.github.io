---
layout: writeup
title: TwoMillion
---

## Overview

This report details my compromise of 'TwoMillion'. [Brief overview of below sections]

Details:
- **Machine:** TwoMillion
- **IP:** 10.10.11.221
- **OS:** Linux
- **Difficulty:** 3.8/10
- **Key Vulnerabilities:** Samba RCE, Cron Job Misconfiguration

*Throughout this write-up, I will be using the IP address I was assigned - 10.10.11.221 - if you are assigned a different IP address, make sure to change it when following along.*\
**OPEN VPN BIT HERE**

## Reconnaissance & Enumeration

As with all penetration testing, we must first start by trying to gather as much information as we can about the IP we have been given. The most common tool for this is `nmap` which can reveal which ports on our target are open. A list of ports is a list of ways we can access the IP address - much more useful than just the IP alone.\
I used the following command:
```bash
nmap -sV -sC 10.10.11.221
```
I used The `-sV` flag to output not just the port, but also what service version is running on it. An outdated service is often a very exploitable vector for attack.\
I also used the flag `-sC` which runs a suite of specialised scripts when attempting to connect to each port to hopefully gather more information about them.
After the scan completes, we can now analyse the output:
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Firstly, we can see that there are two open ports - 22 (SSH) and 80 (HTTP). Each of these ports uses a specific service and version (from `-sV`) and has some additional information below it (from `-sC`).\
Since the SSH is likely secured by a strong password, our first step should be to access the page via HTTP and see what we can learn from its website.\
\
When attempting to connect to `http://2million.htb` (the URL of the IP shown above in the `nmap` results) in my browser, it told me that it was unable to find the site.\
The reason for this is that our browser doesn't know which IP to connect to for this URL, since it is only available via HackTheBox's openvpn network. To allow our browser to know which IP to send requests to for this URL, we need to add an entry in the `/etc/hosts` file.\
The following command pipes the output of `echo` (our line that links the IP address to the URL) into `tee` which opens and appends (`-a`) our entry to `/etc/hosts`.
```bash
echo "10.10.11.221 2million.htb" | sudo tee -a /etc/hosts
```
We should now be able to access the site:
![2million.htb frontpage](../resources/writeups/TwoMillion1.png)

Initial enumeration of the site began with a manual inspection. Looking through the page revealed two interesting endpoints - `/login` and `/invite`.\
The login page, while potentially vulnerable, required an email and password, so we need to register first. The invite page confirms that we can sign up, but only with an invite code.\
While looking through the page's source code for any useful information, I noticed a script `inviteapi.min.js` that was being loaded. After accessing the script and deobfuscating it using Gemini, we could read the `makeInviteCode()` function:
```JavaScript
// This function makes a new invite code.
function makeInviteCode() {
    // Make an AJAX call using jQuery's $.ajax method.
    $.ajax({
        // The HTTP request type is POST.
        type: "POST",
        // The expected data type from the server is JSON.
        dataType: "json",
        // The URL endpoint for the API call.
        url: '/api/v1/invite/how/to/generate',
        // A function to handle a successful response from the server.
        success: function(response) {
            // Log the response to the console.
            console.log(response);
        },
        // A function to handle an error in the request.
        error: function(response) {
            // Log the error response to the console.
            console.log(response);
        }
    });
}
```



## Initial Foothold

Identifying the Vulnerability: Explain how you identified the exploitable flaw. "The Nmap scan revealed Samba version 3.0.20. A quick search using searchsploit confirmed this version is vulnerable to a remote command execution flaw (CVE-XXXX-XXXX)."
The Exploit: Detail the exploitation process step-by-step. If you used a public exploit script, explain the command. If you did it manually, explain the logic.
Gaining Access: Show the screenshot of your shell connection. Explain who you are on the box (whoami) and what your initial limitations are.

user flag:


## Privilege Escalation

Internal Enumeration: This is critical. Explain your methodology. "Now with user-level access, the goal is to become root. My methodology involves checking for SUID binaries, sudo permissions, cron jobs, and running a script like linpeas.sh to automate the search for common vectors."
The Vulnerable Vector: Explain what you found. "The linpeas.sh script highlighted an unusual cron job running as root. Upon inspecting the script, I discovered it was world-writable..."
The Escalation: Detail how you exploited this vector. "I replaced the contents of the script with a reverse shell payload. After waiting for the cron job to execute, I received a new shell on my listening netcat session, now running with root privileges."
Proof: Show the screenshot of whoami returning root and the contents of the root.txt flag.


## Conclusion

Remediation & Mitigation
This is your "Blue Team" section. For each key vulnerability, provide a concise, professional recommendation.
Initial Foothold: "The Samba RCE could be mitigated by updating the Samba service to the latest patched version. As a compensating control, network firewalls should be configured to restrict access to port 445 to only trusted internal IP ranges."
Privilege Escalation: "The privilege escalation was possible due to insecure file permissions on a script executed by a cron job. The script's permissions should be hardened to be owned by root and writable only by the owner (chmod 755). Regular security audits should be performed to detect and correct such misconfigurations."

Conclusion & Key Takeaways
A brief, final paragraph. What did you learn from this box? Was there a new tool you used or a technique you refined?
Example: "The 'Lame' machine was a valuable exercise in exploiting classic, unpatched services. It served as a powerful reminder that consistent patch management is one of the most effective security controls. Furthermore, it reinforced my internal enumeration methodology, leading directly to the privilege escalation vector."
