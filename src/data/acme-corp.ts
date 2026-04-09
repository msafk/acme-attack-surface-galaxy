// ─────────────────────────────────────────────────────────────────────────────
// ACME Corp – Fake Attack Surface Data
// Generated for demo / visualisation purposes only.
// All IPs are in the TEST-NET-3 range (203.0.113.0/24, RFC 5737).
// ─────────────────────────────────────────────────────────────────────────────

export type Severity = "low" | "medium" | "high" | "critical";

export interface OpenPort {
  port: number;
  service: string;
}

export interface Vulnerability {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  realWorldExample: string;
  howToFix: string;
}

export interface Subdomain {
  id: string;
  fqdn: string;
  ip: string;
  cloudflareProtected: boolean;
  openPorts: OpenPort[];
  vulnerabilities: Vulnerability[];
  /** Role label shown in the graph */
  role: string;
}

export interface EmailSecurityWarning {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  realWorldExample: string;
  howToFix: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: "root" | "subdomain" | "email";
  severity: Severity | "none";
  cloudflareProtected: boolean;
  data: Subdomain | EmailSecurityWarning | null;
}

export interface GraphLink {
  source: string;
  target: string;
  label?: string;
}

export interface AcmeCorpData {
  company: string;
  domain: string;
  subdomains: Subdomain[];
  emailSecurityWarnings: EmailSecurityWarning[];
  graph: {
    nodes: GraphNode[];
    links: GraphLink[];
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const PORT_MAP: Record<number, string> = {
  21: "FTP",
  22: "SSH",
  25: "SMTP",
  80: "HTTP",
  443: "HTTPS",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  6379: "Redis",
  8080: "Alt-HTTP",
  8443: "Alt-HTTPS",
  9200: "Elasticsearch",
  27017: "MongoDB",
};

function port(p: number): OpenPort {
  return { port: p, service: PORT_MAP[p] ?? "Unknown" };
}

// ─────────────────────────────────────────────────────────────────────────────
// Vulnerabilities (per subdomain)
// ─────────────────────────────────────────────────────────────────────────────

const vuln_oldApi_elasticsearch: Vulnerability = {
  id: "vuln-001",
  severity: "critical",
  title: "Unauthenticated Elasticsearch Exposes 2 Million Customer Records",
  description:
    "The Elasticsearch instance on old-api.acme-corp.example:9200 is publicly reachable with no authentication layer. " +
    "The index `customers_v1` contains ~2 000 000 records including full names, email addresses, hashed passwords, " +
    "and historical order data. Any actor can query, modify, or delete data via the REST API without credentials.",
  realWorldExample:
    "In 2019, an unprotected Elasticsearch cluster at Autoclerk (a hotel management platform) " +
    "leaked 179 GB of guest records including US military personnel data. The root cause was an " +
    "identical misconfiguration: no X-Pack security and no network-level restriction.",
  howToFix:
    "1. Immediately restrict network access to the cluster with a firewall rule allowing only known application server IPs. " +
    "2. Enable X-Pack security (xpack.security.enabled: true) and set strong passwords for the elastic superuser. " +
    "3. Rotate all credentials that may have been stored in the exposed index. " +
    "4. Audit logs for any unexpected reads or deletes over the past 90 days.",
};

const vuln_staging_mongodb: Vulnerability = {
  id: "vuln-002",
  severity: "critical",
  title: "MongoDB on Staging Accessible with Default Credentials",
  description:
    "The MongoDB 4.2 instance on staging.acme-corp.example:27017 accepts connections from the public internet " +
    "and still uses the factory default admin/admin credential pair. It holds a near-production copy of the " +
    "product catalogue, order history, and a subset of customer PII used for QA.",
  realWorldExample:
    "The 2017 'MongoDB Apocalypse' saw over 27 000 databases wiped and held for ransom within 48 hours " +
    "because operators left port 27017 open and authentication disabled. Attackers used automated scanners " +
    "to identify and exploit targets at scale.",
  howToFix:
    "1. Close port 27017 at the firewall; bind MongoDB to 127.0.0.1 or a private VPC interface only. " +
    "2. Immediately change all database credentials; never use default credentials in any environment. " +
    "3. Enable MongoDB authentication (security.authorization: enabled in mongod.conf). " +
    "4. Scrub real PII from staging; use anonymised fixtures generated with a tool like Faker.",
};

const vuln_jenkins_rce: Vulnerability = {
  id: "vuln-003",
  severity: "critical",
  title: "Jenkins 2.220 Exposed – CVE-2024-23897 Arbitrary File Read / RCE",
  description:
    "The Jenkins instance at jenkins.acme-corp.example runs version 2.220 which is affected by " +
    "CVE-2024-23897. The built-in CLI arg-parsing feature allows unauthenticated users to read arbitrary " +
    "files from the controller file system, and with crafted payloads can achieve remote code execution " +
    "in the context of the jenkins OS user, which has write access to the entire CI/CD pipeline.",
  realWorldExample:
    "CVE-2024-23897 was weaponised within days of disclosure in early 2024, with multiple threat actors " +
    "targeting exposed Jenkins instances to exfiltrate secrets and install cryptocurrency miners. " +
    "Several Fortune 500 supply chains were assessed as compromised.",
  howToFix:
    "1. Immediately upgrade Jenkins to ≥ 2.443 (LTS) or ≥ 2.442 (weekly). " +
    "2. If immediate upgrade is not possible, disable the CLI via 'Manage Jenkins → Security → CLI → Disable'. " +
    "3. Restrict access to the Jenkins UI to the VPN / internal network using a firewall rule. " +
    "4. Audit all pipeline credentials (secrets, SSH keys, API tokens) for potential exfiltration.",
};

const vuln_ftp_anon: Vulnerability = {
  id: "vuln-004",
  severity: "high",
  title: "Anonymous FTP Login Enabled",
  description:
    "The vsftpd server on ftp.acme-corp.example accepts anonymous logins. The anonymous writable " +
    "directory contains deployment scripts, an unencrypted database connection string in deploy.conf, " +
    "and a stale copy of the production .env file dated 8 months ago.",
  realWorldExample:
    "The 2011 vsftpd backdoor incident demonstrated how a compromised FTP server with weak access " +
    "controls can pivot into full host compromise. Anonymous FTP is regularly flagged in PCI-DSS " +
    "audits as an automatic failure criterion.",
  howToFix:
    "1. Disable anonymous FTP in vsftpd.conf (anonymous_enable=NO). " +
    "2. Remove the stale .env and deploy.conf files immediately and rotate every credential they contain. " +
    "3. Consider replacing FTP entirely with SFTP (SSH subsystem) which provides encryption in transit. " +
    "4. Apply firewall rules to restrict FTP access to known partner IP ranges if the service must remain.",
};

const vuln_backup_dirlist: Vulnerability = {
  id: "vuln-005",
  severity: "high",
  title: "Directory Listing Exposes SQL Backup Files",
  description:
    "Apache directory listing is enabled on backup.acme-corp.example. Browsing to / reveals a " +
    "chronological archive of SQL dumps (e.g. acme_prod_2024-11-01.sql.gz) spanning 14 months. " +
    "Each file contains full table exports of the production database including the users, orders, " +
    "and payment_tokens tables.",
  realWorldExample:
    "In 2020 the Keepnet Labs breach began with a researcher discovering an open directory listing on " +
    "an Elasticsearch server containing 5 billion previously leaked records. Exposed backup files are " +
    "a consistent root cause in breach investigations because they bundle months of data in one download.",
  howToFix:
    "1. Disable Apache directory listing globally (Options -Indexes in httpd.conf) or per vhost. " +
    "2. Move backup files behind authenticated access or, preferably, to a private object-storage bucket " +
    "   (S3 / GCS) with no public ACL. " +
    "3. Encrypt backup files at rest using GPG or age before storing them. " +
    "4. Implement retention policies; offsite backups older than 90 days should be deleted or archived to cold storage.",
};

const vuln_legacyShop_magento: Vulnerability = {
  id: "vuln-006",
  severity: "critical",
  title: "Unpatched Magento 2.3 – Multiple Known Exploits (Shoplift / CosmicSting)",
  description:
    "legacy-shop.acme-corp.example runs Magento Open Source 2.3.0, which is end-of-life and " +
    "affected by at least 40 publicly disclosed CVEs. Critical among them are CVE-2024-34102 " +
    "(CosmicSting – unauthenticated XXE leading to RCE) and the Shoplift bundle (SUPEE-5344) " +
    "enabling admin account creation without authentication. The storefront still processes a small " +
    "volume of legacy subscription orders.",
  realWorldExample:
    "In mid-2024, the CosmicSting campaign compromised an estimated 4 000 Magento stores in a single " +
    "weekend, injecting payment card skimmers into checkout pages. Victims included multiple mid-market " +
    "retailers who had not patched their Magento 2.x installations.",
  howToFix:
    "1. Migrate remaining orders off legacy-shop immediately; decommission the host once order history " +
    "   is transferred to the main shop. " +
    "2. If decommission is blocked, apply the latest Magento 2.4.x upgrade path and all security patches. " +
    "3. Place a WAF (Cloudflare, Fastly) in front of the storefront to virtual-patch known exploits. " +
    "4. Perform a forensic review of all web server logs since 2024-06-01 for signs of the CosmicSting " +
    "   IOCs (unusual /rest/V1/guest-carts requests).",
};

const vuln_old_ssl: Vulnerability = {
  id: "vuln-007",
  severity: "medium",
  title: "Expired SSL/TLS Certificate",
  description:
    "The TLS certificate presented by old.acme-corp.example expired 47 days ago. Browsers display " +
    "a full-page warning blocking access. The subdomain still receives traffic from legacy redirect " +
    "links embedded in marketing emails, sending real users into a certificate error state that " +
    "erodes brand trust and creates a phishing opportunity (attackers can serve a valid cert on a " +
    "lookalike domain).",
  realWorldExample:
    "In 2020 Microsoft Teams went down globally for 3 hours because an automation token used to " +
    "renew an internal certificate was itself expired. LinkedIn, Stripe, and the UK government's " +
    "COVID contact-tracing portal have all suffered publicly reported cert expiry incidents.",
  howToFix:
    "1. Renew the certificate immediately using Let's Encrypt (certbot renew) or your CA of choice. " +
    "2. Implement automated renewal via certbot --deploy-hook or cert-manager (Kubernetes) and alert " +
    "   on certificates expiring within 30 days. " +
    "3. Audit all other subdomains for certificates expiring within 60 days. " +
    "4. Update legacy marketing email links to redirect to the canonical www subdomain instead.",
};

const vuln_internalTools_public: Vulnerability = {
  id: "vuln-008",
  severity: "high",
  title: "Internal Tools Dashboard Accidentally Exposed to Public Internet",
  description:
    "internal-tools.acme-corp.example is reachable from the public internet despite being intended " +
    "as an internal-only service. It hosts an admin panel for managing employee accounts, an internal " +
    "metrics dashboard with revenue figures, and a feature-flag management UI connected to the " +
    "production database. No authentication is required to access the metrics and feature-flag views.",
  realWorldExample:
    "In 2021 Twitch suffered a breach partly attributed to an internal tooling dashboard that was " +
    "accessible outside the expected network boundary. Publicly exposed internal admin panels are " +
    "consistently ranked in OWASP's Broken Access Control category as a top vulnerability class.",
  howToFix:
    "1. Immediately restrict the server to accept connections only from the corporate VPN CIDR range. " +
    "2. Add authentication (SSO via Okta / Google Workspace) to every page of the internal tooling site. " +
    "3. Separate the feature-flag service from public-internet-reachable infrastructure; use a private " +
    "   VPC subnet with no internet gateway route. " +
    "4. Conduct an access log review to determine whether any external IPs have accessed the dashboard.",
};

// ─────────────────────────────────────────────────────────────────────────────
// Email Security Warnings
// ─────────────────────────────────────────────────────────────────────────────

const emailWarnings: EmailSecurityWarning[] = [
  {
    id: "email-001",
    severity: "high",
    title: "SPF Record Missing",
    description:
      "acme-corp.example has no SPF (Sender Policy Framework) TXT record in DNS. Without SPF, any " +
      "server on the internet can send email claiming to be from @acme-corp.example, and receiving " +
      "mail servers have no cryptographic mechanism to reject such messages. This directly enables " +
      "phishing and business email compromise (BEC) attacks targeting ACME's customers and partners.",
    realWorldExample:
      "The 2016 Democratic National Committee breach involved spear-phishing emails spoofing " +
      "internal senders. SPF and DMARC were not properly configured, allowing spoofed messages to " +
      "reach inboxes unfiltered. BEC attacks cost businesses $2.9 billion in reported losses in 2023 " +
      "according to the FBI IC3 report.",
    howToFix:
      "Add a TXT record to acme-corp.example DNS: " +
      "\"v=spf1 include:_spf.google.com include:sendgrid.net ~all\". " +
      "Enumerate all legitimate sending services first to avoid blocking valid email. " +
      "Use -all (hard fail) once you are confident the list is complete.",
  },
  {
    id: "email-002",
    severity: "critical",
    title: "DMARC Record Missing",
    description:
      "There is no DMARC (Domain-based Message Authentication, Reporting & Conformance) policy " +
      "published at _dmarc.acme-corp.example. Without DMARC, even if SPF and DKIM are configured, " +
      "there is no instruction to receiving mail servers about what to do with messages that fail " +
      "alignment checks. Attackers can freely send spoofed mail from the domain with high deliverability.",
    realWorldExample:
      "In 2023, a large-scale phishing campaign spoofing Amazon, PayPal, and dozens of retail brands " +
      "succeeded largely because target domains lacked DMARC enforcement policies. Google and Yahoo " +
      "announced in 2024 that bulk senders without DMARC will have mail rejected outright.",
    howToFix:
      "1. Add a TXT record at _dmarc.acme-corp.example: \"v=DMARC1; p=none; rua=mailto:dmarc-reports@acme-corp.example; ruf=mailto:dmarc-forensics@acme-corp.example; fo=1\". " +
      "2. Monitor aggregate reports for 2-4 weeks to identify all legitimate sending sources. " +
      "3. Graduate the policy to p=quarantine, then p=reject once you have confidence in SPF/DKIM alignment. " +
      "4. Use a DMARC reporting service (Postmark, Dmarcian, Valimail) to parse and act on reports.",
  },
  {
    id: "email-003",
    severity: "medium",
    title: "DKIM Key is 1024-bit (Below Recommended 2048-bit)",
    description:
      "The DKIM selector `mail._domainkey.acme-corp.example` publishes a 1024-bit RSA public key. " +
      "NIST deprecated 1024-bit RSA in 2013. A well-resourced adversary can factor a 1024-bit key, " +
      "allowing them to forge valid DKIM signatures for acme-corp.example email, bypassing DMARC " +
      "even with a strict policy in place.",
    realWorldExample:
      "Researchers from Tampere University demonstrated factoring of 1024-bit DKIM keys using " +
      "commodity cloud compute in 2012. As of 2024, academic research suggests the cost is within " +
      "reach of nation-state and well-funded criminal groups. Several payment processors have issued " +
      "advisories requiring vendors to use 2048-bit DKIM.",
    howToFix:
      "1. Generate a new 2048-bit DKIM key pair: `openssl genrsa -out dkim-private.pem 2048 && openssl rsa -in dkim-private.pem -pubout -out dkim-public.pem`. " +
      "2. Publish the new public key under a new selector (e.g. `mail2024._domainkey`) to allow rollover without disruption. " +
      "3. Configure your mail server (Postfix/Google Workspace/SendGrid) to sign with the new key. " +
      "4. After verifying the new selector works, remove the old 1024-bit record.",
  },
  {
    id: "email-004",
    severity: "low",
    title: "SPF Record Uses ~all (Soft-Fail) Instead of -all (Hard-Fail)",
    description:
      "The SPF record for acme-corp.example ends with ~all (soft-fail). This instructs receiving " +
      "mail servers to accept but mark non-authorised senders, rather than rejecting them outright. " +
      "In practice most large mail providers (Gmail, Outlook) treat soft-fail messages identically " +
      "to passing messages unless DMARC enforcement is also in place, negating much of the protection " +
      "SPF is intended to provide.",
    realWorldExample:
      "Security researchers at Agari found that ~60% of Fortune 500 companies using SPF soft-fail " +
      "still had spoofed emails delivered to Gmail inboxes in controlled tests, because DMARC was " +
      "absent or set to p=none. The combination of ~all SPF and missing DMARC is consistently " +
      "exploited in BEC campaigns.",
    howToFix:
      "1. Audit all services that send email on behalf of acme-corp.example (transactional email, " +
      "   marketing platforms, HR tools, support systems). " +
      "2. Ensure each is listed in the SPF include chain. " +
      "3. Change the SPF record terminator from ~all to -all. " +
      "4. Deploy DMARC at p=reject to provide defence-in-depth even if a sending service is missed.",
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Subdomains
// ─────────────────────────────────────────────────────────────────────────────

const subdomains: Subdomain[] = [
  // ── Cloudflare-protected (12 of 30, ~40%) ──────────────────────────────────
  {
    id: "www",
    fqdn: "www.acme-corp.example",
    ip: "203.0.113.1",
    cloudflareProtected: true,
    openPorts: [],
    vulnerabilities: [],
    role: "Main website",
  },
  {
    id: "shop",
    fqdn: "shop.acme-corp.example",
    ip: "203.0.113.2",
    cloudflareProtected: true,
    openPorts: [],
    vulnerabilities: [],
    role: "E-commerce storefront",
  },
  {
    id: "api",
    fqdn: "api.acme-corp.example",
    ip: "203.0.113.3",
    cloudflareProtected: true,
    openPorts: [],
    vulnerabilities: [],
    role: "Public REST API",
  },
  {
    id: "cdn",
    fqdn: "cdn.acme-corp.example",
    ip: "203.0.113.4",
    cloudflareProtected: true,
    openPorts: [],
    vulnerabilities: [],
    role: "Content delivery",
  },
  {
    id: "cdn2",
    fqdn: "cdn2.acme-corp.example",
    ip: "203.0.113.5",
    cloudflareProtected: true,
    openPorts: [],
    vulnerabilities: [],
    role: "Secondary CDN",
  },
  {
    id: "assets",
    fqdn: "assets.acme-corp.example",
    ip: "203.0.113.6",
    cloudflareProtected: true,
    openPorts: [],
    vulnerabilities: [],
    role: "Static asset hosting",
  },
  {
    id: "blog",
    fqdn: "blog.acme-corp.example",
    ip: "203.0.113.7",
    cloudflareProtected: true,
    openPorts: [],
    vulnerabilities: [],
    role: "Marketing blog",
  },
  {
    id: "support",
    fqdn: "support.acme-corp.example",
    ip: "203.0.113.8",
    cloudflareProtected: true,
    openPorts: [],
    vulnerabilities: [],
    role: "Help desk portal",
  },
  {
    id: "status",
    fqdn: "status.acme-corp.example",
    ip: "203.0.113.9",
    cloudflareProtected: true,
    openPorts: [],
    vulnerabilities: [],
    role: "Service status page",
  },
  {
    id: "m",
    fqdn: "m.acme-corp.example",
    ip: "203.0.113.10",
    cloudflareProtected: true,
    openPorts: [],
    vulnerabilities: [],
    role: "Mobile web",
  },
  {
    id: "beta",
    fqdn: "beta.acme-corp.example",
    ip: "203.0.113.11",
    cloudflareProtected: true,
    openPorts: [],
    vulnerabilities: [],
    role: "Beta feature preview",
  },
  {
    id: "portal",
    fqdn: "portal.acme-corp.example",
    ip: "203.0.113.12",
    cloudflareProtected: true,
    openPorts: [],
    vulnerabilities: [],
    role: "Partner / B2B portal",
  },

  // ── Exposed (18 of 30) ────────────────────────────────────────────────────
  {
    id: "mail",
    fqdn: "mail.acme-corp.example",
    ip: "203.0.113.13",
    cloudflareProtected: false,
    openPorts: [port(25), port(443)],
    vulnerabilities: [],
    role: "Mail server",
  },
  {
    id: "staging",
    fqdn: "staging.acme-corp.example",
    ip: "203.0.113.14",
    cloudflareProtected: false,
    openPorts: [port(80), port(443), port(27017)],
    vulnerabilities: [vuln_staging_mongodb],
    role: "Staging environment",
  },
  {
    id: "dev",
    fqdn: "dev.acme-corp.example",
    ip: "203.0.113.15",
    cloudflareProtected: false,
    openPorts: [port(22), port(80), port(8080)],
    vulnerabilities: [],
    role: "Developer sandbox",
  },
  {
    id: "old",
    fqdn: "old.acme-corp.example",
    ip: "203.0.113.16",
    cloudflareProtected: false,
    openPorts: [port(80), port(443)],
    vulnerabilities: [vuln_old_ssl],
    role: "Legacy marketing site",
  },
  {
    id: "admin",
    fqdn: "admin.acme-corp.example",
    ip: "203.0.113.17",
    cloudflareProtected: false,
    openPorts: [port(443), port(8443)],
    vulnerabilities: [],
    role: "Admin dashboard",
  },
  {
    id: "vpn",
    fqdn: "vpn.acme-corp.example",
    ip: "203.0.113.18",
    cloudflareProtected: false,
    openPorts: [port(443), port(22)],
    vulnerabilities: [],
    role: "VPN gateway",
  },
  {
    id: "git",
    fqdn: "git.acme-corp.example",
    ip: "203.0.113.19",
    cloudflareProtected: false,
    openPorts: [port(22), port(443)],
    vulnerabilities: [],
    role: "Self-hosted Gitea",
  },
  {
    id: "ftp",
    fqdn: "ftp.acme-corp.example",
    ip: "203.0.113.20",
    cloudflareProtected: false,
    openPorts: [port(21), port(22)],
    vulnerabilities: [vuln_ftp_anon],
    role: "File transfer server",
  },
  {
    id: "test",
    fqdn: "test.acme-corp.example",
    ip: "203.0.113.21",
    cloudflareProtected: false,
    openPorts: [port(80), port(8080), port(3306)],
    vulnerabilities: [],
    role: "QA / test environment",
  },
  {
    id: "legacy-shop",
    fqdn: "legacy-shop.acme-corp.example",
    ip: "203.0.113.22",
    cloudflareProtected: false,
    openPorts: [port(80), port(443), port(3306)],
    vulnerabilities: [vuln_legacyShop_magento],
    role: "Legacy Magento storefront",
  },
  {
    id: "backup",
    fqdn: "backup.acme-corp.example",
    ip: "203.0.113.23",
    cloudflareProtected: false,
    openPorts: [port(80), port(22)],
    vulnerabilities: [vuln_backup_dirlist],
    role: "Backup file server",
  },
  {
    id: "jenkins",
    fqdn: "jenkins.acme-corp.example",
    ip: "203.0.113.24",
    cloudflareProtected: false,
    openPorts: [port(8080), port(8443), port(22)],
    vulnerabilities: [vuln_jenkins_rce],
    role: "CI/CD Jenkins server",
  },
  {
    id: "wiki",
    fqdn: "wiki.acme-corp.example",
    ip: "203.0.113.25",
    cloudflareProtected: false,
    openPorts: [port(443), port(80)],
    vulnerabilities: [],
    role: "Internal wiki (Confluence)",
  },
  {
    id: "hr",
    fqdn: "hr.acme-corp.example",
    ip: "203.0.113.26",
    cloudflareProtected: false,
    openPorts: [port(443), port(5432)],
    vulnerabilities: [],
    role: "HR information system",
  },
  {
    id: "finance",
    fqdn: "finance.acme-corp.example",
    ip: "203.0.113.27",
    cloudflareProtected: false,
    openPorts: [port(443), port(5432)],
    vulnerabilities: [],
    role: "Finance / ERP system",
  },
  {
    id: "old-api",
    fqdn: "old-api.acme-corp.example",
    ip: "203.0.113.28",
    cloudflareProtected: false,
    openPorts: [port(80), port(9200), port(22)],
    vulnerabilities: [vuln_oldApi_elasticsearch],
    role: "Deprecated v1 API server",
  },
  {
    id: "demo",
    fqdn: "demo.acme-corp.example",
    ip: "203.0.113.29",
    cloudflareProtected: false,
    openPorts: [port(80), port(443)],
    vulnerabilities: [],
    role: "Sales demo environment",
  },
  {
    id: "internal-tools",
    fqdn: "internal-tools.acme-corp.example",
    ip: "203.0.113.30",
    cloudflareProtected: false,
    openPorts: [port(80), port(443), port(3389)],
    vulnerabilities: [vuln_internalTools_public],
    role: "Internal admin tooling",
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Severity roll-up helper
// ─────────────────────────────────────────────────────────────────────────────

function worstSeverity(vulns: Vulnerability[]): Severity | "none" {
  const order: (Severity | "none")[] = ["critical", "high", "medium", "low", "none"];
  const found = vulns.map((v) => v.severity);
  for (const s of order) {
    if (found.includes(s as Severity)) return s as Severity;
  }
  return "none";
}

// ─────────────────────────────────────────────────────────────────────────────
// Graph construction
// ─────────────────────────────────────────────────────────────────────────────

const ROOT_ID = "acme-corp.example";

const graphNodes: GraphNode[] = [
  {
    id: ROOT_ID,
    label: "acme-corp.example",
    type: "root",
    severity: "none",
    cloudflareProtected: false,
    data: null,
  },
  ...subdomains.map((s): GraphNode => ({
    id: s.id,
    label: s.fqdn,
    type: "subdomain",
    severity: worstSeverity(s.vulnerabilities),
    cloudflareProtected: s.cloudflareProtected,
    data: s,
  })),
  ...emailWarnings.map((e): GraphNode => ({
    id: e.id,
    label: e.title,
    type: "email",
    severity: e.severity,
    cloudflareProtected: false,
    data: e,
  })),
];

const EMAIL_SECURITY_ID = "email-security";
const emailSecurityHub: GraphNode = {
  id: EMAIL_SECURITY_ID,
  label: "Email Security",
  type: "email",
  severity: "critical",
  cloudflareProtected: false,
  data: null,
};
graphNodes.push(emailSecurityHub);

const graphLinks: GraphLink[] = [
  // Root → each subdomain
  ...subdomains.map((s): GraphLink => ({
    source: ROOT_ID,
    target: s.id,
    label: "subdomain",
  })),
  // Root → email security hub
  { source: ROOT_ID, target: EMAIL_SECURITY_ID, label: "email security" },
  // Email security hub → each warning
  ...emailWarnings.map((e): GraphLink => ({
    source: EMAIL_SECURITY_ID,
    target: e.id,
    label: e.severity,
  })),
];

// ─────────────────────────────────────────────────────────────────────────────
// Main export
// ─────────────────────────────────────────────────────────────────────────────

export const ACME_CORP_DATA: AcmeCorpData = {
  company: "ACME Corp",
  domain: "acme-corp.example",
  subdomains,
  emailSecurityWarnings: emailWarnings,
  graph: {
    nodes: graphNodes,
    links: graphLinks,
  },
};
