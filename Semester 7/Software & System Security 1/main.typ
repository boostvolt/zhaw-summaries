#import "../../packages/cheatsheet/src/lib.typ": *

#set text(font: "Helvetica", lang: "en", region: "gb")

#let author = "Jan Kott"
#let title = "Software & System Security 1"

#show: boxedsheet.with(
  title: title,
  authors: author,
  title-align: left,
  title-number: true,
  homepage: "boostvolt",
  title-delta: 2pt,
  scaling-size: false,
  font-size: 5.5pt,
  line-skip: 5.5pt,
  x-margin: 10pt,
  y-margin: 20pt,
  num-columns: 4,
  column-gutter: 2pt,
)

= Basics
#concept-block(body: [
  #inline("CIA")
  - *Confidentiality*: Protect sensitive data from unauthorised read access
  - *Integrity*: Protect data and systems from unauthorised modification
  - *Availability*: Information must be available when needed

  #inline("Terminology")
  - *Vulnerability*: Defect (bug/flaw) that attacker can exploit
  - *Threat*: Possible danger exploiting a vulnerability. Intentional (attacker) or accidental (fire)
  - *Threat agent*: The attacker | *Threat action*: Actual attack procedure
  - *Exploit*: Actual attack taking advantage of vulnerability (malware, commands)
  - *Asset*: Anything of value to organisation (HW, SW, data) - also valuable to attacker
  - *Risk*: Criticality of threat/vulnerability. _risk = probability x impact_
  - *Countermeasure*: Action/device/process reducing risk (removes vulnerability or reduces harm)
  - *CVE*: Common Vulnerabilities and Exposures, standard naming for public vulnerabilities (e.g., CVE-2018-0297)

  #inline("Defect Types")
  - *Security Bug*: Implementation error (e.g., `gets()` no bounds check). Found by code inspection.
  - *Security Design Flaw*: Design error (e.g., weak PRNG seed). Found by threat modelling.
  - ~50/50 split → design matters as much as code!

  #inline("Malware Types")
  - *Malware*: Malicious software to disrupt, gather info, or gain access
  - *Virus*: Spreads via host programs/documents, requires user interaction
  - *Worm*: Standalone, spreads automatically. Cycle: scan → exploit vulnerability → infect → repeat
  - *Trojan*: Disguises as legitimate software, does not self-replicate
  - *Ransomware*: Encrypts data, demands payment for decryption key
  - *Drive-by download*: Browser/plugin vulnerability → auto-execute malicious code from compromised site

  #inline("Reactive Countermeasures")
  - *Penetrate & Patch*: Fix when discovered. _Problems: exploit often before patch, users don't patch, rushed patches add vulnerabilities_
  - *Network Security Devices*: WAF (Web App Firewall), IPS (Intrusion Prevention System) filter traffic before reaching app. _Problems: can't detect all attacks, expensive config_
  - Both are signs of *poor software security practice*!

  #inline("Proactive Countermeasures")
  - *Secure Development Lifecycle (SDL)*: Security activities throughout development - only approach that works
  - Must think like an attacker to design countermeasures
  - _Not 100% secure: new attacks emerge → reactive measures still needed_
])

= Secure Development Lifecycle (SDL)
#concept-block(body: [
  #inline("Overview")
  - Applies to *any* dev process (waterfall, iterative, agile) → adopt incrementally
  - Early activities *prevent* defects, late activities *detect* them
  - Fix early = 10-100x cheaper than fixing late

  #inline("Security Activities")
  #image("assets/secure-development-lifecycle-security-activities.png", width: 72%)
  1. *Security requirements*: From functional requirements, technology-agnostic (e.g., credit card transmission → require encrypted channel)
  2. *Threat modelling* (→ finds 50% flaws): Think like attacker, identify threats → derive more security requirements (e.g., fire in server room → need data redundancy)
  3. *Security design & controls*: Choose mechanisms for requirements (2FA, role-based access, etc.)
  4. *Secure coding* (→ finds 50% bugs): Implement correctly, use checklists, compiler warnings
  5. *Code review*: Automated tools + manual inspection
  6. *Penetration testing*: Attack own system to verify requirements fulfilled + find bugs. Human testers more effective than automated tools
  7. *Security operations*: Patching, monitoring, backups, learn from attacks

  #inline("Security Risk Analysis (horizontal activity)")
  Runs throughout all phases. Rate risk of found problems: _risk = probability x impact_ → decide: accept or mitigate
])

= 7 (+1) Kingdoms of Software Security Errors (SDL 3 & 4)
#concept-block(body: [
  #inline("1. Input Validation & Representation")
  Encoding can bypass validation (same data, different representation).
  - *Buffer overflow*: Write beyond buffer → modify program flow, crash, inject code
  - *Injection attacks*: Command/SQL/XML injection → execute arbitrary commands
  - *Cross-site scripting (XSS)*: Execute JS in victim's browser → steal credentials
  - *Path traversal*: Access files via `../../etc/shadow`

  #inline("2. API Abuse")
  - *Dangerous functions*: `gets()` in C has no bounds check → never use
  - *Unchecked return values*: Ignoring returns → null reference → crash
  - *Wrong security assumptions*: DNS lookup for auth → DNS can be spoofed

  #inline("3. Security Features")
  Never invent your own → use proven solutions.
  - *Insecure randomness*: Weak PRNG or predictable seed → weak keys
  - *Incomplete access control*: Inconsistent checks → privilege escalation
  - *Weak encryption*: Deprecated algorithms (MD5, DES, RC4)

  #inline("4. Time & State")
  Humans think sequential, computers work parallel → unforeseen interactions.
  - *Deadlock*: Poor locking mechanisms → availability problems
  - *TOCTOU*: Time of Check to Time of Use — attacker changes resource between check and use
  - *Session ID reuse*: Same ID across auth boundaries → session hijacking
  - *Timing attacks*: Response time reveals info (e.g., password check duration)

  #inline("5. Error Handling")
  - *Information leakage*: Error messages expose internals (stack traces, SQL queries)
  - *Empty/broad catch blocks*: Ignoring exceptions → unexpected behaviour, crashes

  #inline("6. Code Quality")
  - Memory leaks, unreleased resources (files, sockets), deprecated functions, null dereference, uninitialised variables

  #inline("7. Encapsulation")
  - *Hidden form fields*: Not visible but easily readable/modifiable
  - *CSRF*: Attacker makes requests in victim's authenticated session

  #inline("(*) Environment")
  - *Insecure compiler optimisation*: Compiler removes "unnecessary" security code (e.g., memory clearing)
  - *Framework issues*: Weak session ID length/randomness
])

= Web Application Security Testing (SDL 5 & 6)
#concept-block(body: [
  #inline("Injection Attacks")
  *Core idea*: User input treated as code, not data

  #subinline("SQL Injection")
  - *Testing*: Insert `'` → SQL error (HTTP 500, different response) = vulnerable
  - *Blind SQLi* (no visible errors):
    - *Time-based*: ```sql SLEEP(5)``` causes delay if vulnerable
    - *Boolean-based*: Different response for true/false conditions (e.g., ```sql ' AND 1=1--``` vs ```sql ' AND 1=2--```)
  - *Tautology (always-true)*: ```sql ' OR ''='``` makes WHERE always TRUE:
    - ```sql WHERE (userid=? AND password='') OR ''=''``` → first part fails, but ```sql ''=''``` is TRUE
  - *UNION attack*:
    1. *Find column count*: Try ```sql ' UNION SELECT 1--```, ```sql ' UNION SELECT 1,2--```, etc. until no error. Use Burp Intruder (Sniper) to automate.
    2. *Extract data*: ```sql ' UNION SELECT col1,col2,... FROM table--``` (columns must match count AND types)
  - *Schema discovery*:
    - Tables: ```sql UNION SELECT 1,TABLE_NAME,3,... FROM INFORMATION_SCHEMA.SYSTEM_TABLES--```
    - Columns: ```sql UNION SELECT 1,COLUMN_NAME,3,... FROM INFORMATION_SCHEMA.SYSTEM_COLUMNS WHERE TABLE_NAME='target'--```
  - *Comments*: Cut off rest of query (e.g., ```sql admin'--``` ignores ```sql AND pass='...'```)
    - MySQL: ```sql --``` + space after, or ```sql #```
    - Others: ```sql --```
  - *Multiple queries*: `;` separator only works if server uses `executeBatch()`
  - *INSERT injection*: ```sql userpass'), ('admin', 'Superuser', 'adminpass')--```
  - *Counter*:
    - *Prepared statements*: Query parsed with `?` placeholders, input bound separately → always data, never code
    - *Escaping* (weaker): Transform `'` → `\'`, error-prone (encoding issues, incomplete escaping)

  #subinline("OS Command Injection")
  - *Cause*: App executes OS commands with user input (Java `Runtime.exec()`, PHP `system()`)
  - *Testing*: Find input used in commands (e.g., filename field), append command separator:
    - Linux: ```sh ; whoami``` or ```sh | whoami```
    - Windows: ```sh & ipconfig```
    - If quoted path: close quote first ```sh "; whoami```
  - *Counter*: Use IO classes instead of OS runtime, whitelist allowed chars, minimal privileges

  #subinline("JSON/XML Injection")
  - *Cause*: App builds JSON/XML by inserting user input into template
  - *Attack*: Inject closing chars + new key/element → last occurrence wins
    - JSON: `myPassword","admin":"true` | XML: `</password><admin>1</admin>`
  - *Counter*: Escape/blacklist special chars (`"`, `{`, `}`, `<`, `>`)

  #subinline("XXE (XML External Entity)")
  - *Cause*: XML parser processes external entity references in DOCTYPE
  - *Attack*: Send crafted XML via POST with entity pointing to resource:
    ```xml
    <!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>
    <data>&x;</data>
    ```
  - *Result*: App returns file content. Also usable for SSRF (Server-Side Request Forgery → internal network requests)
  - *Counter*: Disable external entities in parser, prefer JSON over XML

  #inline("Authentication & Session")
  #subinline("Broken Authentication")
  - *Username enumeration*: Find valid usernames before brute-forcing
    - Login behaves differently for existing/non-existing users (message, response time)
    - Account creation: app complains if username already taken
    - *Counter*: Vague error messages ("Login failed"), CAPTCHA on account creation
  - *Online brute-force*:
    - *Prerequisite*: Unlimited login attempts without account lockout
    - Burp Intruder: Capture login, mark username + password, remove Cookie header, *Cluster bomb* attack
    - Find valid credentials: Look for *outliers* (different status code or response length)
    - *Counter*: Rate limiting (e.g., 60s delay after 3 failures). Do NOT lock accounts → enables DoS (Denial of Service). Enforce password quality + check against common password lists
  - *Password reset*: Security questions often guessable/findable, can chain weak resets across providers
    - *Counter*: No self-service reset for high-value apps, hard security questions, temp password/link to registered email (valid once, short expiry)

  #subinline("Broken Session Management")
  - *Session ID guessing*: Test for weak/predictable session IDs
    - Burp Sequencer: Collect many session IDs, analyze randomness (entropy)
    - Good: ≈115 bits entropy. Poor: ≈2 bits = easily guessable
  - *Session fixation*: Attacker gives own session ID to victim
    - Works if app supports session ID in URL (e.g., `;jsessionid=...`)
    - Basic: Attacker logged in → sends link with session ID → victim uses attacker's account → victim adds credit card → attacker sees it
    - *Powerful variant*: Attacker creates unauthenticated session → victim clicks link → victim logs in → if session ID not rotated, attacker now has authenticated session
  - *Counter*:
    - Use long random session IDs (≥128 bits entropy)
    - *Change session ID after login* (prevents fixation)
    - Only use cookies for session ID (not URL)
    - Session inactivity timeout (e.g., 10 min)

  #inline("XSS (Cross-Site Scripting)")
  *Core idea*: Attacker injects JS code into web page viewed by other users → JS executes in victim's browser

  - *Attack possibilities*: Steal cookies (`document.cookie`), fake login form, send requests in victim's session
  - *POST via XSS*: Hidden form + auto-submit (`document.forms[0].submit()`)
  - *Testing*: ```js <script>alert("XSS");</script>``` → if popup appears, vulnerable

  #subinline("Reflected (Server) XSS")
  - Victim clicks link with JS in parameter → server reflects JS back → browser executes it
  - Example: `http://xyz.com/search?q=<script>...</script>`
  - *Requires*: App doesn't validate input AND doesn't sanitize output

  #subinline("Stored (Server) XSS")
  - Attacker stores JS permanently in app (forum post, comment, profile)
  - Victim views page → JS executes (no link click needed)

  #subinline("XSS Countermeasures")
  - *Output sanitization* (primary): Replace `<` `>` `"` with `&lt;` `&gt;` `&quot;`
  - *Input validation*: Reject/filter JS in input (but not always possible)
  - *HttpOnly cookie flag*: Blocks `document.cookie` access (XSS can still send requests - browser auto-attaches cookies)
  - *Browser XSS Auditor*: Detects if response contains same JS as request (Chrome, Edge, Safari - NOT Firefox)
  - *CSP (Content Security Policy)*: Specify allowed sources for scripts
    - `Content-Security-Policy: default-src 'self'; script-src scripts.example.com`
    - Embedded JS not executed → must load from external files → attacker can't inject inline scripts

  #subinline("DOM-based XSS")
  - Server NOT involved → client JS reads untrusted data (URL, DOM) and processes insecurely
  - *`#` fragment*: Attacker puts JS after `#` in URL → not sent to server (server can't detect) → but client JS reads it via DOM
  - *Dangerous functions*: `unescape()` (decodes URL-encoded chars), `eval()` (executes string as JS)
  - Example: `?data=19#data=19;alert('XSS')` → `eval("13 * 19;alert('XSS')")`
  - *Counter*: Avoid `eval()`, validate/sanitize in client-side JS

  #inline("Broken Access Control")
  #subinline("Function Level")
  User accesses function they shouldn't (e.g., `/admin/vieworders`)
  - *Finding URLs*: Guess patterns (`/customer` → `/admin`), access logs, open-source code
  - *Counter*: Check user role/permissions before granting URL access (usually framework-configurable)

  #subinline("Object Level")
  User abuses function to access *objects* they shouldn't (e.g., `?pid=1` → `?pid=2`)
  - *Exposed identifiers*: file name, user ID, product ID, database key
  - More common (framework handles URL access, but object checks must be coded manually)
  - *Counter*: Verify user owns object on every request; derive IDs from session instead of exposing in params

  #inline("CSRF (Cross-Site Request Forgery)")
  Force authenticated user to execute unwanted action. Browser attaches cookies regardless of link source.
  - *GET*: `<img src="https://shop.com/transfer?to=attacker" width="1" height="1">`
  - *POST*: Hidden form + `document.forms[0].submit()` in zero-size iframe, or `fetch()` with `credentials: "include"`
  - *Multi-step*: `fetch()` + `async/await` chains requests
  - *Counter*:
    - CSRF token: Random per-user token in session, include in requests, server compares
    - SameSite cookie: `None` (all) | `Lax` (GET only, default) | `Strict` (never) — still use CSRF tokens!

  #inline("Testing Tools")
  #subinline("Dynamic (Vulnerability Scanners)")
  Crawls running app → sends attack patterns → analyzes response
  - *ZAP*: Detects SQLi, XSS, missing CSRF tokens, cookie attributes
  - *Limit*: Only tests what crawler finds; struggles with forms; auth/state issues

  #subinline("Static (Code Analyzers)")
  Analyzes source code or bytecode without running app
  - *Fortify*: Source code - detects CSRF, info leaks, hardcoded passwords
  - *SpotBugs*: JAR bytecode (Java only)
  - *Limit*: Must understand framework (may miss SQLi/XSS)

  Both miss logic vulnerabilities (access control, param tampering) → manual testing required
])

= Buffer overflow & race cond (SDL 3 & 4)

#concept-block(body: [
  #inline("Buffer overflows")
  Modify the program flow, crash the program, inject (malicious) own code, access sensitive information...

  #grid(
    columns: (auto, auto),
    // image("buffo0.png"),
    [
      *`area` execution (leaf function)* \
      `rbp == rsp` bc we use *Red Zone* opti. Local vars stored using neg. offsets of `rbp` (no `subq` instr.)
    ],

    // image("buffo1.png"),
    [
      *`main` return (non-leaf)*
      `rsp` points to top of stack to clearly delimitate `main`'s memory (no Red Zone opti)
    ],
  )

  #subinline("Exploit example")
  ```c
  void processData(int socket) {
    char buffer[256], tempBuffer[12];
    int count = 0, position = 0;

    /* Read data from socket and copy it into buffer */
    count = recv(socket, tempBuffer, 12, 0);
    while (count > 0) {
      memcpy(buffer + position, tempBuffer, count)
      position += count;
      count = recv(socket, tempBuffer, 12, 0);
    }

    return 0;
  }
  ```

  #grid(
    columns: (28%, auto),
    // image("buffoexploit.png"),
    [
      - Attacker sends more than `256 bytes` through socket.
      - Bytes `265` to `272` overwrite `ret address`. Attacker can replace it with the beginning addr. of buffer.
      - Bytes `0` to `264` contain attack code.
      - Attack code runs with same privileges as program.
    ],
  )

  - *Counters:* Check boundaries for any input/output op, avoid `gets`, `strcpy`, static code ana & fuzzing, forbid exec of code in mem data segments,  Address Space Layout Randomisation (ASLR),

  #subinline("Stack canaries")
  - Random 8 bytes val gen at start if program
  - Pushed to stack right after `old rbp`
  - Before returning to calling function, stack value is compared to saved generated value
  - Program crashes/terminates if they don't match

  #inline("Race conditions")
  #subinline("TOCTOU (Time of Check Time of Write)")
  ```c
  if(!access(file, W_OK)) {
    printf("Enter data to write to file: ");
    fgets(data, 100, stdin);
    fd = fopen(file, "w+");
    if (fd != NULL) {
      fprintf(fd, "%s", data);
    }
  } else {  /* user has no write access */
    fprintf(stderr, "Permission denied when trying to open %s.\n", file);
  }
  ```
  Attacker can change the file `file` points to after the `if` check passed but before writing starts, e.g. using a symlink to a sensitive file he shouldn't access \
  *Counters:*
  - use as little functions that take filename as arg as possible. Use it for initial file access and return a reusable file descriptor (e.g. used to check write perm).
  - Let the OS handle perm checks and avoid running prog as root user.

  ```java
  public class SessionIDGenerator {
    private static Random rng = new Random();
    private static String newSessionID

    public static void createSessionID() {
      byte[] randomBytes = new byte[16];
      rng.nextBytes(randomBytes);
      newSessionID = Util.toHexString(randomBytes);
    }

    public static String getSessionID() {
      return newSessionID;
    }
  }
  ```
  1. Thread A calls `create`
  2. Thread B calls `create`
  3. Thread A calls `get`. But it will get User B's session ID.
])

= Fundamental Security Principles (SDL 1, 2 & 3)
#concept-block(body: [
  #inline("1. Secure the Weakest Link")
  Overall security determined by weakest component (SW, HW, protocols, but also users, admins, processes). \
  Attackers target weakest link → fix highest risks first (not easiest). Identify via: threat modelling, pentests, risk analysis.

  #inline("2. Defense in Depth")
  Multiple diverse defensive strategies. If one layer fails, another may prevent attack.
  - Don't assume internal network is safe just because firewall exists → encrypt internal traffic too, harden hidden servers
  - Beyond prevention: *Prevent* (password requirements) → *Detect* (monitor failed logins) → *Contain* (lock accounts) → *Recover* (force password reset)

  #inline("3. Fail Securely")
  Failure must not compromise security. Caused by: *poor code*, *poor procedures*, *poor configuration*.
  - *Poor code*: `isAdmin = true; try { isAdmin = checkPerms(); } catch {...}` → exception leaves `isAdmin = true`
  - *Poor procedures*: Spare firewall configured to "let through everything" for quick replacement
  - *Poor config*: System accepts old insecure protocol versions → *Version Downgrading Attack* (MITM forces old protocol: NTLM→LM, TLS 1.2→SSL 3.0, 5G/4G/3G→GSM)

  #inline("4. Principle of Least Privilege")
  User/program gets least amount of privileges necessary. Often violated because it "makes things easier".
  - Don't run programs with full access rights → exploiting them gives attacker full access
  - Split functionality across apps (admin dashboard internal-only vs customer app public)
  - DB user with full rights + SQLi → attacker accesses all tables

  #inline("5. Separation of Privileges")
  No single user can carry out AND conceal an action (four-eyes principle). \
  Separate: approval ↔ execution ↔ monitoring.
  - E-banking: transfers >10k need manager approval
  - Dev ≠ tester ≠ deployer (prevents malicious dev from including backdoors)
  - DB admin ≠ system admin (can't alter own logs)

  #inline("6. Secure by Default")
  Default config must be secure: 2FA on, auto-updates on, firewall on, minimal default permissions, no default passwords.

  #inline("7. Minimize Attack Surface")
  Attack surface = all points where attacker can attack (open ports, APIs, forms, any reachable code). \
  Fewer features → less code → smaller attack surface. Disable unused features, use firewalls to hide internal services.

  #inline("8. Keep it Simple")
  Simple to develop/maintain/test securely. Simple for users to use securely.
  - Re-use proven components (don't invent own crypto)
  - Security-critical functions in one place (single `checkAccess()`)
  - Users shouldn't make security decisions → don't let them disable security features

  #inline("9. Avoid Security by Obscurity")
  Security by obscurity = secure because attackers don't know internals. Nearly always fails (reverse engineering: disassemblers, decompilers). \
  Only good as *redundancy* on top of real security measures.
  - *Code obfuscation types*: Source/Binary (unreadable equivalent), Data (split vars, change encoding), Control Flow (reorder logic, inject junk), Preventive (strip metadata, rename `calculate()`→`x()`)

  #inline("10. Don't Trust User Input and Services")
  User may be attacker, 3rd party service may be compromised. Always validate received data.
  - *Whitelisting* > blacklisting: define what is allowed (blacklisting easy to forget something)
  - Don't try fixing invalid data → just reject it
])

= Developing Secure SSR Web Applications (SDL 3 & 4)

#concept-block(body: [
  #inline("Spring Security Config")
  `SecurityConfig` class: central place for auth, access control, CSRF, session settings. \
  `@EnableWebSecurity` marks config class. `SecurityFilterChain` bean defines rules. \
  *Order matters:* Rules applied top→bottom, *first match wins* → put specific rules before general!
  ```java
  http.authorizeHttpRequests(auth -> auth
    .dispatcherTypeMatchers(FORWARD, ERROR).permitAll() // internal forwards/errors
    .requestMatchers("/", "/public/**", "/css/*").permitAll()
    .requestMatchers("/admin/**").hasAnyRole("MARKETING", "SALES")
    .anyRequest().denyAll() // secure default!
  ).requiresChannel(c -> c.anyRequest().requiresSecure()); // HTTP→HTTPS
  ```

  #inline("Preventing Information Leakage")
  Unhandled exceptions leak internals (stack traces, SQL). *Fix:* Standard error pages.
  - Add `error.html` in `/templates/` → generic message for all errors
  - Specific: `404.html`, `500.html` in `/templates/error/`
  - *Remove* debug settings from `application.properties` (include-exception, include-stacktrace)

  #inline("XSS Prevention (Data Sanitation)")
  *Always sanitize* regardless of input validation. Thymeleaf: `th:text` = safe (encodes `<`), `th:utext` = *unsafe*. \
  Sanitize ALL external data: user input, DB, files, 3rd party systems.

  #inline("SQL Injection Prevention")
  *Never* string concatenation. Use *prepared statements* with `?` placeholders.
  ```java
  String sql = "SELECT * FROM Product WHERE desc LIKE ?";
  jdbcTemplate.query(sql, mapper, "%" + desc + "%"); // safe - '?' escaped
  ```

  #inline("JPA (Jakarta Persistence API)")
  ORM framework: maps objects ↔ database tables. *Prevents SQLi* when used correctly.
  - *Entity classes:* `@Entity`, `@Table(name="Product")`, `@Id` for primary key
  - *JPQL:* Query language for entities. Use *named parameters* (`:param`) not string concat!
    ```java
    @Query("SELECT p FROM Product p WHERE p.desc LIKE CONCAT('%', :desc, '%')")
    List<Product> findByDesc(@Param("desc") String desc); // safe
    ```
  - *CrudRepository:* Auto-generates safe queries: `findById()`, `save()`, `delete()`, `findByDescriptionContaining(String)` = auto LIKE
  - *Danger:* `EntityManager` + string concatenation or native queries = *SQLi possible!*

  #inline("Secure Password Storage")
  *Never* plaintext or simple hash → use *slow hash functions* (bcrypt, Argon2, PBKDF2, scrypt).
  - Plaintext/simple hash → SQLi/DB compromise = direct access or dictionary attack
  - Salt + fast hash → still crackable (100M/sec on GPU)
  - *bcrypt*: salt + many rounds, designed to resist GPU attacks

  #inline("Authentication Setup (Spring)")
  DB-based auth requires: `UserDetailsService` (loads user from DB) + `BCryptPasswordEncoder` (verifies password).
  ```java
  @Service class UserService implements UserDetailsService {
    public UserDetails loadUserByUsername(String u) { /*load from DB*/ }
  }
  // SecurityConfig beans:
  @Bean AuthenticationManager authManager() {
    var p = new DaoAuthenticationProvider();
    p.setUserDetailsService(userService); p.setPasswordEncoder(pwEncoder());
    return new ProviderManager(p);
  }
  @Bean PasswordEncoder pwEncoder() { return new BCryptPasswordEncoder(); }
  ```

  #inline("Authentication Mechanisms")
  #subinline("HTTP BASIC")
  Server returns 401 → browser shows dialog → credentials in `Authorization: Basic <base64>` header on *every* request. \
  *Limitation:* No logout without closing browser (credentials cached).

  #subinline("FORM-based (Preferred)")
  Login form submits to server → on success, stores user/role in session → session ID in cookie. \
  *Always POST* (GET exposes password in URL/logs). Logout via POST to `/logout` destroys session.
  ```java
  http.formLogin(f -> f.loginPage("/public/login").failureUrl("/public/login?error=true").permitAll())
      .logout(l -> l.logoutSuccessUrl("/public/products?logout=true"));
  ```
  *Login form requirements:* action=`/public/login`, params: `username`, `password`.

  #inline("Role-Based Access Control")
  Define roles → assign to users → map roles to resources in `SecurityConfig`.
  ```java
  .requestMatchers("/admin/deletepurchase/*").hasRole("SALES") // more specific first!
  .requestMatchers("/admin/**").hasAnyRole("MARKETING", "SALES")
  ```
  *URL patterns:* `/admin/*` = direct children only, `/admin/**` = all descendants.

  #subinline("Method-Level Security")
  Alternative to SecurityConfig rules: `@EnableMethodSecurity` in config class, then:
  ```java
  @PreAuthorize("hasRole('SALES')") // or combine with method params:
  @PreAuthorize("hasRole('USER') and #userId == authentication.principal.id")
  public void updateUser(int userId) { ... }
  ```
  *Advantages:* Fine-grained control, works for internal calls (not just HTTP). Can combine both for *defense in depth*.

  *UI hiding not enough!* `sec:authorize="hasRole('SALES')"` hides buttons in Thymeleaf, but user can still craft requests → *always enforce server-side*.

  #inline("CSRF Protection")
  Spring Security default: CSRF token stored in session, included as hidden field `_csrf` in forms (POST only).
  ```html
  <input type="hidden" name="_csrf" value="random-token"/>
  ```
  Server compares received token with session token. Attacker can't guess token → CSRF blocked.

  *SameSite:* `Lax` (default) blocks POST CSRF but not GET → *never use GET for state changes!* \
  Use *both* CSRF tokens AND SameSite for defense in depth.

  #inline("Secure Session Handling")
  *Cookie attributes:*
  - `Secure`: Only HTTPS (prevents sniffing over HTTP)
  - `HttpOnly`: No JS access (`document.cookie` blocked → limits XSS impact)
  - `SameSite=Lax`: Blocks cross-site POST (CSRF protection)
  - No `expires`: Session cookie (deleted on browser close)

  *Session ID requirements:* Long & random (≥128 bits), *change on login*, destroyed on logout.

  #subinline("Session Fixation")
  Spring Security *automatically rotates session ID after login* (only with built-in auth, not custom login!).

  #subinline("Logout")
  POST to `/logout` destroys session, creates new anonymous session. Configure redirect:
  `.logout(l -> l.logoutSuccessUrl("/public/products?logout=true"))`

  ```toml
  # application.properties
  server.servlet.session.cookie.http-only=true
  server.servlet.session.cookie.secure=true
  server.servlet.session.cookie.same-site=lax
  server.servlet.session.timeout=10m
  ```

  #inline("Input Validation (Bean Validation)")
  Jakarta EE framework: *whitelisting* approach (define what's allowed).
  ```java
  public class Purchase {
    @NotNull(message = "Missing")
    @Pattern(regexp = "^[a-zA-Z']{2,32}$", message = "Invalid name")
    private String firstname;
    @CreditCardCheck // custom annotation
    private String creditCardNumber;
  }
  ```
  Common annotations: `@NotNull`, `@Size(min, max)`, `@Pattern(regexp)`, `@Min`, `@Max`, `@Email` \
  *Gotcha:* `@Pattern` returns true for null → always combine with `@NotNull`!

  *Controller:* `@Valid` triggers validation, `BindingResult` captures errors.
  ```java
  public String save(@ModelAttribute @Valid Purchase p, BindingResult result) {
    if (result.hasErrors()) { return "checkout"; } // show form again with errors
  ```
  *Template:* `th:if="${#fields.hasErrors('firstname')}"` + `th:errors="*{firstname}"`

  #subinline("Custom Validation")
  Create annotation with `@Constraint(validatedBy = MyValidator.class)` + class implementing `ConstraintValidator<AnnotationType, FieldType>` with `isValid()` method.

  #subinline("Encoding Attacks")
  Input validation alone may not prevent attacks if app decodes data later.
  - Attacker encodes `<script>` as `%3Cscript%3E` (URL encoding) → passes validation (only letters/digits/%)
  - If app URL-decodes before output → XSS possible
  - *Best practice:* Don't decode, or decode first then validate. Sanitation (encode `<` → `&lt;`) is primary defense.
])

= Secure CSR webapps (SDL 3 & 4)

#concept-block(body: [
  #inline("JSON Web Tokens")
  #subinline("Structure")
  Header
  ```json
  {
    "alg":"HS256" // which MAC algo to use
  }
  ```
  Payload
  ```json
  {
    "iss":"Marketplace", // issuer
    "sub":"alice", // subject
    "exp":"1749281266" // expiry date
  }
  ```
  MAC (Message Authentication Code)
  ```
  HMAC-SHA256(header + "." + payload, key) // key known only by REST service server/backend
  ```
  Final full token
  #text(fill: red, "Base64(header)")\.#text(fill: green, "Base64(payload)")\.#text(fill: blue, "Base64(MAC)")
  #subinline("Props")
  - cannot be forged due to secret HMAC key
  - expires
  - verifying the HMAC is fast
  - stateless (self-contained)
  - URL safe (no char encoding)
  #subinline("How")
  1. User authenticates using username+pw
  2. Backend checks the pair in DB. If correct, it generates a JWT and sends it back
  3. Client includes the JWT in every request
  4. Backend extracts the username from the token
  #inline("Erros")
  - `CustomAccessDeniedHandler`: access control error (insufficient perm)
  - `InvalidParameterException`: Auth failed or invalid ID passed
  - `MethodArgumentNotValidException`: `@Valid` is used and validation fails
  - `ConstraintViolationException`: Bean Validation annotations are used with method parameters (e.g., @`Min` and `@Max`) and validation fails
  - `MethodArgumentTypeMismatchException`: Thrown if a path parameter has the wrong type (e.g., a purchase ID of type int is expected, but a string is received)
  - `RuntimeException`: Thrown if storing a purchase in the database does not work
  #inline("Config")
  ```java
  // filter every request with the auth checker
  http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
  .exceptionHandling(exception -> exception
  .accessDeniedHandler(accessDeniedHandler)
  .authenticationEntryPoint(authenticationEntryPoint))
  .cors(Customizer.withDefaults());

  CorsConfiguration config = new CorsConfiguration();
  config.setAllowedOrigins(Arrays.asList("*"));
  config.setAllowedMethods(Arrays.asList("OPTIONS", "GET", "POST", "DELETE"));
  config.setAllowedHeaders(Arrays.asList("*"));
  UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
  source.registerCorsConfiguration("/rest/**", config);
  return source
  ```
  #inline("CORS")

])

// TODEL -- course outline
// #image("Screenshot 2025-12-06 185927.png")
