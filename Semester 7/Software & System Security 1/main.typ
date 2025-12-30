#import "lib.typ": *

#set text(font: "Helvetica")
#set text(
  lang: "en",
  region: "gb",
)


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
  numbered-units: false,
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
  Runs throughout all phases. Rate risk of found problems: _risk = probability × impact_ → decide: accept or mitigate
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

= Web app attacks (SDL 5 & 6)
#concept-block(body: [
  Many web apps, security low and critical data (banking, e-commerce...)
  OWASP: Top Ten, Testing Guide, App Secu Verif Standard, WebGoat (bad app example)
  // #image("webappsbasic.png")
  #inline("Injection attacks")
  #subinline("SQL")
  - Tools: ```sql OR ``==`` ```, ```sql UNION interesting_cols FROM interesting_table```, ```sql ; UPDATE employee SET password = 'foo'-```
  - If multiple params: use ```sql -- ``` to make rest of query a comment. In MySQL the space at the end is required.
  - Use ```sql ;``` to execute separate queries, only if server uses `executeBatch()`
  - Insert user: ```sql userpass'), ('admin', 'Superuser', 'adminpass')--```
  - *Testing*:
    - Set password to single-quote ' and see if DB returns error. Inject `SLEEP`
    - *Getting table names*: ```sql SELECT * FROM user_data WHERE last_name = Smith' UNION SELECT 1,TABLE_NAME,3,4,5,6,7 FROM INFORMATION_SCHEMA.SYSTEM_TABLES--```
      1. We assume `user_data` has 7 columns, all `int` except the 2nd one which is `string`
      2. We set the `UNION` query so that all columns but the 2nd are string literals (arbitrary numbers)
      3. We set the 2nd column to `TABLE_NAME` and query the `INFORMATION_SCHEMA.SYSTEM_COLUMNS`
      4. Second column contains one table name per row
    - *Getting column names of a table*: ```sql SELECT * FROM user_data WHERE last_name = Smith' UNION SELECT 1,COLUMN_NAME,3,4,5,6,7 FROM INFORMATION_SCHEMA.SYSTEM_COLUMNS WHERE TABLE_NAME = 'EMPLOYEE'--```
      3. We set the 2nd column to `COLUMN_NAME` and query the `INFORMATION_SCHEMA.SYSTEM_COLUMNS` for table `EMPLOYEES`
      4. Second column contains one column name per row
  - *sqlmap (Automation)*:
    - *Check for vuln*: ```sh sqlmap -r request.txt -p account_name```
      - `-r request.txt`: HTTP request recorded in file
      - `-p account_name`: Specify target parameter
    - *List schemas/databases*: ```sh sqlmap -r request.txt --dbs```
    - *List tables*: ```sh sqlmap -r request.txt -D PUBLIC --tables```
      - `-D PUBLIC`: Specify the schema/database
    - *Dump table content*: ```sh sqlmap -r request.txt -D PUBLIC -T EMPLOYEE --dump```
      - `-T EMPLOYEE`: Specify the table
  - *Countermeasures:* Prepared statements, all inputs are pre-compiled and special chars are escaped (```java $sth = prepare("SELECT id FROM users WHERE name=? AND pass=?"); execute($sth, $name, $pass);``` yields ```sql SELECT id FROM users WHERE name='\' OR \'\'=\'' AND pass='\' OR \'\'=\'';```)
  #subinline("OS Cmd")
  - Java `Runtime.exec()` instead of `FileReader`/`FileInputStream`, PHP `system()`
  - *Test*: Analyse REST request, e.g. `HelpFile` field. Append `"` after filename and check for err. Append `; ipconfig`/` & ipconfig` (nix/msft). Might need to prepend `"` if app uses file path.
  - *Counter*:
    - use IO classes instead of OS runtime
    - use character whitelisting (ban quotes...)
    - run process with minimal privieges
  #subinline("JSON/XML")
  - *JSON*: app inserts data inside of JSON -> you can overwrite previous keys, since the last occurrence matters. Insert: `myPassword","admin":"true`
  - Same principle for *XML*
  - *Counter:* blacklist curly brackets, special chars
  \
  \
  #subinline("XML External Entitiy Injection")
  Attacker makes a manual POST request with a special XML body:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE query [
    <!ENTITY attack SYSTEM "file:///etc/passwd">
  ]>
  <comment>
    <text>&attack;</text>
  </comment>
  ```
  The app will display the password file content instead as the comment text.
  - *Counter:* blacklist < and >, disabled ext. entities in XML parser

  #inline("Auth & session")
  #subinline("Broken auth")
  - Attacker gets credentials (weak pw, reset pw)
  - Prerequ: unlimited login attempts allowed
  - *Brute-force*: try common usernames and pws, email enumeration (time or msg), create account and see if email taken. *Remove cookie headers for new session* \
    *Counter:* vague msg ("Login failed"), CAPTCHA to rate limit accnt creation
  - *Pw reset*:
    1. Attck calls Amazon and usurps using security quest (name, email and billing address) to log-in
    2. Adds credit card
    3. Calls again, then adds 2nd email
    4. Uses 2nd email to pw reset, sets own pw \
    *Counter:* no reset pw feat and force phone call, use hard security questions, issue temp new pw, issue unique pw reset lin
  #subinline("Broken session mngmt")
  - Attacker gets session ID (guess, exposed, timeout issue, bad rotation, fixation...)
  - Session ID: random, used to ID user, generated when logged in
  - *Session fixation*: Attacker tricks the user into using the web app with their (attack) session ID, e.g. by sending a URL with the session ID. Then attacker waits for user to log in, add credit card... \
    *Counter:* long random 128bit UIDs, change ID for each login, use cookies not URL, use session timeouts (10min)

    #inline("XSS (cross-site scripting)")
    Inject own JS code that is executed in other user's browser, without having to modify server code
    #subinline("Stored (persist)")
    Attacker places attack script directly as normal data in the web app (e.g. as a post comment). When user views it, browser executes the `script` tag.
    #subinline("Reflected (non-persist)")
    1. Make user click a link that makes server send back malicious script (e.g. as search query result: `http://www.xyz.com/search.asp?searchString=<script>ATTACK CODE</script>"`)
    2. App displays "Search results for ...". The script tag is added to DOM and executed, not displayed.
    - *Note*: both require poor serve code (no sanitation), storing+displaying of data
    - *Test*: `<script>alert("XSS worked");</script>`
    // #image("xssjack.png", width: 90%)
    Can make form submission *automatic* by putting `send_postdata()` in a script tag \
    *Counters to reflected:*
    - replace `<script>alert("XSS");</script>` with `&lt;script&gt;alert(&quot;XSS&quot;);&lt;/script&gt;`
    - *XSS Auditor* detects that the JS code returned by server is the same as the one sent by the browser's previous REST request (*not in Firefox*). Can be bypassed with a local proxy.  (diff emitting address)
    - CSP: specify which web content can be loaded from which locations (domains or hosts). ` Content-Security-Policy: default-src 'self'; img-src *; media-src media1.com media2.com; script-src scripts.supersecure.com`: same, imgs from anywhere, audio/video from media1 and media2, script from scripts.supersecure.com.
    #subinline("DOM-based XSS")
    Server not involved.
    - Variant 1 (`unescape`):
      0. App displays `document.location.href` to the user, *using `unescape()`*
      1. Attacker makes user click `ubuntu.test/attackdemo/general/DOMbased_XSS1.html#<script>alert("XSS");</script>`
      2. App adds script to DOM, which is executed but not displayed
      *Note*: cannot be caught by server bc the `#` is not included in the request. It doesn't work without `unescape` bc the characters will be URL-encoded.
    - Variant 2 (`eval`):
      0. ```js <script>
          var data =  document.location.href.substring(document.location.href.lastIndexOf("data=") + 5);
          var compute = "13 * " + data;
          var result = eval(compute);
          document.write(result);
        </script>```
      1. Click `ubuntu.test/attackdemo/general/DOMbased_XSS3.html?data=19#data=19;alert('XSS');`
      2. App reads last ocuurence of `data`: `data=19;alert('XSS');`
      3. Eval computes `13*19; alert("XSS");`
      *Note*: cannot be caught by server bc the `#` is not included in the request. `unescape` not used so `>`, `<` and `"` cannot be used (bc URL-encoded).
    - *Counter*: avoid `unescape` and `eval`, avoid using JS to render elements controlled by user,
    #inline("Broken Access Control")
    Access data or execute actions for which attacker isn't authorised
    #subinline("Function level")
    Access unauthorised function. E.g.: `/admin/post` EP does not check if user is actually admin
    #subinline("Object level")
    Attacker can use an authorised function in a manner that gives access to unauthorised objects (resources) \
    E.g.: non-randomised resource IDs (username, filename, PID...) \
    *Counter*: auth checks for every action and resource access, don't include resource IDs in URL or requests
    #inline("Cross-Site Request Forgery (CSRF)")
    Force another user to execute an unwanted action while they are authenticated
    - *GET*:
      0. Victim is logged into `shop.com`
      1. Victim clicks on bad `attacker.com` link, which display an image: `<img src="https://shop.com/transfer?amount=1000&to=attacker" width="1" height="1">`
      2. The image triggers a GET request to `shop.com`. Browser automatically attaches the `shop.com` cookie, so the request is valid.
    - *POST*:
      0. Victim is logged into `shop.com`
      1. Victim clicks on bad `attacker.com` link, which contains a 0x0 Iframe, which contains an auto-submitting form
    - *`fetch`*
      ```js
      <script>
          fetch("shop.com", {
            method: "POST",
            credentials: "include",
            headers: {"Content-Type": "application/x-www-form-urlencoded"},
            body: "title=ATTACK&message=SUCCESS&SUBMIT=submit"
          });
      </script>
      ```
      *Note:* works bc GET and POST are not subject to the Same Origin Policy
    - *Counter*:
      - Use user session token stored in session storage. Pass it in REST bodies. Compare sent, received and stored tokens.
      - `Set-Cookie: SameSite`. `None` cookies are attached to all x-site requs, `Lax` cookies attached to GET x-site requs, `Strict` never attached. `lax` good but must ensure GET requs do not modify app state.
    #inline("Testing tools")
    - *ZAP*: Scans all requests then tries famous vulnes. But uses fixed vals that can block the app (e.g. incorrect form values)
    - *Fortify*: static code analyser. Doesnt see SQL injection or XSS.
    - *Spotbug*: binary (JAR) analyser
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

= Fundamental Security Principles (SDL 1, 2, 3)
#concept-block(body: [
  Battle-tested, true back then, now and in the future. Tech-independent.

  #inline("1. Secure the weakest link")
  Attackers target the weakest component. Fix high risk vulnes first. To identify:  threat modelling, penetration tests, and risk analysis
  #inline("2. Defense in depth")
  1. Defend multiple layers, not just the outter one (e.g. don't assume servers can communicate unencrypted bc you have setup a firewall and inner network is safe)
  2. Don't rely only on prevention.
    1. Prevent (_long, safe pw requs_)
    2. Detect (_monitor large num of failed login_)
    3. Contain (_lock hacked accounts_)
    4. Recover (_ask users to reset pws, monitor attack IPs_)
  #inline("3. Fail securely")
  - *Version Downgrading Attack*: man in the middle convinces client and server that t.he other only supports old (vulnerable) protocol version. Server is configed to accept this.
  - *Fail open vulne*: `isAdmin` initialised to `true`. Function that sets it to the actual value throws an error. Error is caught and `if` check is executed. `isAdmin` is still `true` so sensitive code runs.
    ```java
    boolean isAdmin = true;
    try {
      isAdmin = checkPermissions();
    } catch (Exception ex) {
      log.write(ex.toString());
    }
    if(isAdmin) {
      // sensitive
    }
    ```
  #inline("4. Principle of Least Privilege")
  Keep separate apps for users with separate needs (admin dashboard)
  #inline("5. Separation of Privileges")
  - Preventing that a single user can carry out and conceal an action (or an attack) completely on his own \
  - Separating the entity that approves an action, the entity that carries out an action, and the entity that monitors an action
  - E.g. _Different people are responsible for development vs testing+approval of deployment_
  #inline("6. Secure by Default")
  Default config must be secure. \
  Enforce 2FA, auto security updates, firewall on by default, minimal default permissions, no default pw (or force to change it)
  #inline("7. Minimise attack surface")
  Include only necessary features, use packet-filtering firewalls to keep internal services hidden from Internet
  #inline("8. Keep it simple")
  Easier to maintain. Users shouldn't have to make important security decisions.
  - Re-use proven software components
  - Implement security-critical functions only once and place them in easily identifiable program components (e.g., in a separate security package)
  - Do not allow the users to turn off important security features
  #inline("Avoid Security by Obscurity")
  Security by Obscurity = system is secure bc attackers don't know how its internals work. \
  Good only as redundancy on top of other security measures. \
  Reverse eng: disassembler, decompilers.
  - *Source/Binary*: Transforms code into a functionally equivalent, unreadable version to protect IP during public delivery.
  - *Data*: Obscures storage/structures (e.g., splitting variables, changing encoding, promoting scalars to objects).
  - *Control Flow*: Reorders logic and injects false conditionals/junk code to break decompiler flow while preserving output.
  - *Preventive*: Targets RE tools by stripping metadata and renaming identifiers to gibberish (e.g., `calculate()` -> `x()`).
  #inline("Don't Trust User Input and Services")
  Always validate the received data. Use defensive prog. \
  Prefer *whitelisting* over *blacklisting* (i.e. define what is allowed, not what is forbidden). Don't try fixing invalid data, just reject it.
])

= Secure SSR webapps (SDL 3 & 4)

#concept-block(body: [
  Little client code, server returns full HTML pages. \
  *Warning:* in Spring Security, rules cascade in reverse CSS order: higher rule has priority
  // #image("market.png")
  #inline("DB permissions")
  // #image("dbperms.png")
  #inline("Spring config")
  `@EnableWebSecurity`: marks class as Spring Security config
  ```java
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
    .requiresChannel(channel -> channel.anyRequest().requiresSecure())
    .csrf(csrf-> csrf.disable());
    return http.build();
  }
  ```
  - `authorizeHttpRequest`: all requests are permitted without authentication (per default, Spring Security requires authentication for all requests)
  - `requiresChannel`: all requests to HTTP are redirected to HTTPS
  - `csrf`: disable Cross-Site Request Forgery protection
  #inline("Preventing Information leakage in Error Messages")
  1. Add Spring templates for each type of errors (`500.html`, ...) to show a generic message
  2. Remove the following from `application.properties`:
    ```toml
    server.error.whitelabel.enabled=false
    server.error.include-exception=true
    server.error.include-message=always
    server.error.include-stacktrace=always
    ```
  3. Catch errors and `return 0` inside `catch` blocks
  #inline("Data Sanitation")
  // #image("brianisinthekitchen.png")
  Risk of Reflected XSS vulne (`<script>alert("XSS")</script>`) \
  2 fixes:
  1. Input validation: Do not accept search strings that include JavaScript code
  2. Data sanitation: Encode critical control characters before the search string is included in the webpage (e.g., replace `<` with `&lt;`) (`th:text` in Thymeleaf) \
    *Required* because:
    1. Users might want to search for JS code
    2. Input validation might be turned off for new user needs in the future
  *Important*: perform sanitation for all content that comes from external components (i.e. not the server code): client, database, file...
  #inline("Secure Database Access (SQL inj)")
  Use prepared statements
  ```java
  String sql = "SELECT * FROM Product WHERE Description LIKE ?";
  return jdbcTemplate.query(sql, new ProductRowMapper(), "%" + description + "%");
  ```

  ```java
  String sql = "INSERT INTO Purchase (Firstname, Lastname, CreditCardNumber, TotalPrice) "
  + "VALUES (?, ?, ?, ?)";
  return jdbcTemplate.update(sql, purchase.getFirstname(), purchase.getLastname(),
  purchase.getCreditcardnumber(), purchase.getTotalprice());
  ```
  #subinline("Bad JPA examples")
  Good: Always extend `CrudRepository`.
  Note: JPQL does not support UNION \

  Used JPA directly via class `EntityManager`and used JPQL query using string concatenation. ```sql no-match%' OR '%' = '```
  ```java
  public class ProductVulnerableRepository {
    @Persis§§ tenceContext
    private EntityManager entityManager;
    public List<Product> findByDescriptionContaining(String description) {
      Query query = entityManager.createQuery("SELECT p FROM Product p
      WHERE p.description LIKE '%" + description + "%'");
      return query.getResultList();
    }
  ```
  `EntityManager` is used, together with a native query and string concatenation
  ```java
  public List<Product> findByDescriptionContaining(String description) {
    Query query = entityManager.createNativeQuery("SELECT * FROM Product
    WHERE Description LIKE '%" + description + "%'");
    List<Object[]> results = query.getResultList();
    List<Product> products = new ArrayList<>();
    Product product;
    for (Object[] result : results) { // copy from results to products }
    return products;
  }
  ```
  #inline("Authentication and Access Control")
  #subinline("Secure Storage of Passwords")
  No plaintext or level-1 hashes. Use complex hashing (bcrypt, Argon2...) or 5000+ rounds of fast hashing (SHA-512, `Hash = SHA-512(SHA-512(...|salt|password))`).
  *bcrypt*: `$<version>$<cost>$<salt><hash>` (cost = rounds, salt&hash char counts)
  #subinline("Authentication Mechanism")
  - *HTTP basic auth*: shows a login dialog when server returns a 401, send the username+pw as a (base64-encoded) HTTP Authorisation Header in *every* future REST call. *Can only be cleared by closing the browser.* There is no logout feature.
    ```java http
    .authorizeHttpRequests(...)
    .httpBasic(withDefaults()) ```
  - *Form auth*:
    *Always use POST not GET* (GET includes the form data as URL params)
    ```java
    http
    .authorizeHttpRequests( ... )
    .formLogin(formLoginConfigurer-> formLoginConfigurer
    .loginPage("/public/login")
    .failureUrl("/public/login?error=true")
    .permitAll())
    ```
    #subinline("CSRF protection (Cross-Site Request Forgery)")
    Set `SameSite` to _Lax_ in `application.properties`

    #subinline("Sessions")
    `Set-Cookie: session-id=28A46...; expires=Fri, 23-Dec-2035 11:09:37 GMT; Domain=www.example.com; Path=/myexample; Secure; HttpOnly; SameSite=Lax`
    - `session-id=...`: The name & value of the cookie session ID. Must be long and random.
    - `expires`: if no expiry date is used, the cookie is deleted when closing the browser (*good for session cookies*)
    - `Domain`, `Path`: Any request to resources below `www.example.com/myexample/` includes the cookie
    - `Secure`: Only send the cookie over HTTPS
    - `HttpOnly`: JavaScript cannot access the cookie via `document.cookie`
    - `SameSite`: Specifies when cookies should be included in cross-site requests (_Lax_: only GET requests)

    In `application.properties`:
    ```toml
    server.servlet.session.cookie.http-only=true
    server.servlet.session.cookie.secure=true
    server.servlet.session.timeout=10m
    ```

    #subinline("Input validation")
    ```java
    @GetMapping("/public/products")
    public String productsPage(@ModelAttribute @Valid ProductSearch productSearch, BindingResult bindingResult, Model model) {
      if (bindingResult.hasErrors()) {
        model.addAttribute("products", new ArrayList<Product>());
        productSearch.setDescription("");
        model.addAttribute("productSearch", productSearch);
      }


    public class ProductSearch {
      @Size(max = 50, message = "No more than 50")
      private String description = "";
    ```

    `@Valid` tells Spring to enforce the `@Size` constraint. It stores the result in `BindingResult`. If there is an error, we show an empty product list.
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
