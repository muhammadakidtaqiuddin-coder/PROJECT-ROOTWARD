# Security Policy

RootWard is a read-only privilege-escalation auditor. This policy explains how to report a security problem **in RootWard itself**, and what to do if RootWard shows you a weakness on a system that belongs to someone else.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| Earlier than 1.0.0 | No |

## Reporting a vulnerability in RootWard

### Who to tell
The maintainers of this repository (team **Sudo Squad**). Please report **privately**. Do not open a public issue, pull request or discussion for a vulnerability.

### How to report
1. **Preferred:** use GitHub private vulnerability reporting. On the repository page open the **Security** tab and choose **Report a vulnerability**.
2. **Alternative:** email the team at `muhammadakidtaqiuddin@gmail.com`. Do not put exploit details in a public place.

<!-- TODO (repository owner, Akid): turn on Settings > Code security > Private vulnerability reporting, otherwise option 1 does not exist. Then fill in the team contact address above. -->

Please include:
- what you found and which file or option is affected;
- the RootWard version or commit (`git rev-parse --short HEAD`);
- your operating system and Python version;
- the steps to reproduce it, ideally with a small input;
- what you think the impact is.

### When to expect a reply
RootWard is a student project maintained by volunteers, so these are targets, not guarantees:

| Step | Target |
|---|---|
| Acknowledge your report | within 3 days |
| First assessment (confirmed, not confirmed, or need more detail) | within 7 days |
| Fix or mitigation for a confirmed issue | within 30 days |

We will keep you informed, and we will credit you in the release notes if you want to be named.

### Coordinated disclosure
Please give us a reasonable time to fix the problem before you share details publicly. We ask for **90 days** from your report, or until a fixed release is published, whichever comes first. If we cannot fix it in that time we will tell you why and agree a new date with you.

### What counts as a vulnerability in RootWard
Examples of issues we want to hear about:
- bypassing the **scope check** so that a non-loopback target is accepted;
- bypassing or removing the **legal banner** or the **kill switch**;
- making RootWard **write, change or delete** anything outside the output directory, or modify the audited system in any way (it is meant to be read-only);
- a **crafted file name, hostname, crontab line, or `sudo -l` output** that makes RootWard crash, run a command, or write outside the output directory;
- the tool **sending data over the network** (it must never do this);
- a report file created with **unsafe permissions** or one that overwrites another file.

### What does not count
- Findings that RootWard reports about *your own* machine. That is its job.
- A weakness on a machine you scanned. See the next section.
- A missing check or a false positive or false negative. Please open a normal public issue for those.
- Problems that need you to already have root and to edit RootWard's own source files.

## If RootWard reveals a weakness on a system that is not yours

You should not be running RootWard on a system without the owner's authorization (see the Rules of Engagement in the [README](README.md#rules-of-engagement-roe)). If you came across the issue legitimately:

1. **Stop.** Do not exploit the weakness to prove it, and do not copy any data.
2. **Tell the owner or administrator privately.** Say what you found, where, and how to fix it (RootWard's remediation text is a good start).
3. **Give them reasonable time** to fix it. A common period is 90 days.
4. **Do not publish** details of the weakness until it is fixed, or until the owner agrees.
5. **Keep your report file private.** RootWard writes it with owner-only permissions in `output/`, which is excluded from git. Do not share it, attach it to public issues, or commit it.

## Handling of data

RootWard does not collect, transmit or store personal data. It makes no network connections. Any report it writes stays in a local directory on the machine you ran it on and is labelled with the hostname and a timestamp. It describes weaknesses of that machine, so treat it as sensitive and delete it when it is no longer needed.

## Safe harbor

We will not take action against people who find and report a vulnerability in RootWard in good faith, follow this policy, avoid harming others and do not access data that is not theirs. This applies only to RootWard. It gives **no permission** to test any other system. Unauthorized access to computer systems may violate the Computer Crimes Act 1997 (Act 563) of Malaysia and other laws.
