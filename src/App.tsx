import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import ForceGraph3D from "react-force-graph-3d";
import { ACME_CORP_DATA } from "./data/acme-corp";
import type { Severity, Vulnerability, EmailSecurityWarning } from "./data/acme-corp";
import * as THREE from "three";

// ─── types ────────────────────────────────────────────────────────────────────

type AppPhase = "landing" | "scanning" | "galaxy";

type NodeKind =
  | "root"
  | "subdomain-cf"   // cloudflare-protected subdomain
  | "subdomain-exp"  // exposed subdomain
  | "ip"
  | "port-safe"
  | "port-risky"
  | "vuln"
  | "email-hub"
  | "email-warn";

interface GNode {
  id: string;
  label: string;
  kind: NodeKind;
  val: number;
  color: string;
  subdomainId?: string;
  vuln?: Vulnerability;
  emailWarn?: EmailSecurityWarning;
  fixed?: boolean;
  // runtime – three.js object managed by graph
  __threeObj?: THREE.Object3D;
  x?: number; y?: number; z?: number;
}

interface GLink {
  source: string;
  target: string;
}

interface FixedSet {
  vulns: Set<string>;
  emails: Set<string>;
}

// ─── severity helpers ─────────────────────────────────────────────────────────

const SEV_COLOR: Record<Severity, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#3b82f6",
};
const SEV_SCORE: Record<Severity, number> = {
  critical: 20,
  high:     12,
  medium:   6,
  low:      3,
};

const BASE_RISK = 30;
const MAX_PENALTY =
  [...ACME_CORP_DATA.subdomains.flatMap((s) => s.vulnerabilities),
   ...ACME_CORP_DATA.emailSecurityWarnings]
    .reduce((a, v) => a + SEV_SCORE[(v as Vulnerability | EmailSecurityWarning).severity], 0);

function calcRisk(fixed: FixedSet) {
  let penalty = 0;
  for (const s of ACME_CORP_DATA.subdomains) {
    for (const v of s.vulnerabilities) {
      if (!fixed.vulns.has(v.id)) penalty += SEV_SCORE[v.severity];
    }
  }
  for (const w of ACME_CORP_DATA.emailSecurityWarnings) {
    if (!fixed.emails.has(w.id)) penalty += SEV_SCORE[w.severity];
  }
  const raw = BASE_RISK + Math.round(((MAX_PENALTY - penalty) / MAX_PENALTY) * (100 - BASE_RISK));
  return Math.min(100, Math.max(0, raw));
}

function riskColor(score: number) {
  if (score < 40) return "#ef4444";
  if (score < 70) return "#f59e0b";
  return "#4ade80";
}

// ─── scan phases ──────────────────────────────────────────────────────────────

const SCAN_PHASES = [
  "Enumerating subdomains...",
  "Resolving IPs...",
  "Detecting services...",
  "Checking email security...",
];
const SCAN_TOTAL_MS = 3000;
const PHASE_MS = SCAN_TOTAL_MS / SCAN_PHASES.length;

// ─── graph data builder ───────────────────────────────────────────────────────

function buildGraph(fixed: FixedSet): { nodes: GNode[]; links: GLink[] } {
  const nodes: GNode[] = [];
  const links: GLink[] = [];

  // Root
  nodes.push({
    id: "root",
    label: "ACME Corp",
    kind: "root",
    val: 20,
    color: "#FFD700",
  });

  // Email hub
  nodes.push({
    id: "email-hub",
    label: "Email Security",
    kind: "email-hub",
    val: 10,
    color: "#f87171",
  });
  links.push({ source: "root", target: "email-hub" });

  // Email warnings
  for (const w of ACME_CORP_DATA.emailSecurityWarnings) {
    const isFix = fixed.emails.has(w.id);
    nodes.push({
      id: w.id,
      label: w.title,
      kind: "email-warn",
      val: 6,
      color: isFix ? "#4ade80" : "#f87171",
      emailWarn: w,
    });
    links.push({ source: "email-hub", target: w.id });
  }

  // Subdomains
  for (const s of ACME_CORP_DATA.subdomains) {
    const hasUnfixedVuln = s.vulnerabilities.some((v) => !fixed.vulns.has(v.id));
    const sdColor = s.cloudflareProtected
      ? "#6b7280"
      : hasUnfixedVuln
      ? "#ef4444"
      : "#4ade80";
    const sdKind: NodeKind = s.cloudflareProtected ? "subdomain-cf" : "subdomain-exp";

    nodes.push({
      id: `sd-${s.id}`,
      label: s.cloudflareProtected ? `🔒 ${s.fqdn}` : s.fqdn,
      kind: sdKind,
      val: 10,
      color: sdColor,
      subdomainId: s.id,
    });
    links.push({ source: "root", target: `sd-${s.id}` });

    if (!s.cloudflareProtected) {
      // IP node
      const ipId = `ip-${s.id}`;
      nodes.push({
        id: ipId,
        label: s.ip,
        kind: "ip",
        val: 8,
        color: "#22d3ee",
        subdomainId: s.id,
      });
      links.push({ source: `sd-${s.id}`, target: ipId });

      // Port nodes
      for (const p of s.openPorts) {
        const risky = [9200, 27017, 6379, 3306, 5432, 21, 3389].includes(p.port);
        const portId = `port-${s.id}-${p.port}`;
        nodes.push({
          id: portId,
          label: `${p.port} ${p.service}`,
          kind: risky ? "port-risky" : "port-safe",
          val: 3,
          color: risky ? "#ef4444" : "#4ade80",
          subdomainId: s.id,
        });
        links.push({ source: ipId, target: portId });
      }

      // Vulnerability nodes
      for (const v of s.vulnerabilities) {
        const isFix = fixed.vulns.has(v.id);
        nodes.push({
          id: v.id,
          label: v.title,
          kind: "vuln",
          val: 10,
          color: isFix ? "#4ade80" : "#ef4444",
          vuln: v,
          subdomainId: s.id,
        });
        links.push({ source: `sd-${s.id}`, target: v.id });
      }
    }
  }

  return { nodes, links };
}

// ─── components ───────────────────────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: Severity }) {
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 10px",
        borderRadius: 9999,
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: 1,
        textTransform: "uppercase",
        background: SEV_COLOR[sev],
        color: "#fff",
      }}
    >
      {sev}
    </span>
  );
}

interface DetailPanelProps {
  node: GNode | null;
  onClose: () => void;
  onFix: (node: GNode) => void;
  fixed: FixedSet;
  fixing: string | null;
}

function DetailPanel({ node, onClose, onFix, fixed, fixing }: DetailPanelProps) {
  const isFixed =
    node?.vuln ? fixed.vulns.has(node.vuln.id) :
    node?.emailWarn ? fixed.emails.has(node.emailWarn.id) : false;

  const isFix = fixing === node?.id;

  const detail = node?.vuln ?? node?.emailWarn ?? null;

  return (
    <AnimatePresence>
      {node && (
        <motion.div
          key={node.id}
          initial={{ x: 400, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 400, opacity: 0 }}
          transition={{ type: "spring", damping: 28, stiffness: 220 }}
          style={{
            position: "fixed",
            top: 0,
            right: 0,
            bottom: 0,
            width: 380,
            background: "rgba(10,10,20,0.97)",
            borderLeft: "1px solid #1e293b",
            overflowY: "auto",
            padding: "24px 20px",
            zIndex: 50,
            boxSizing: "border-box",
          }}
        >
          <button
            onClick={onClose}
            style={{
              position: "absolute",
              top: 16,
              right: 16,
              background: "none",
              border: "none",
              color: "#64748b",
              fontSize: 22,
              cursor: "pointer",
              lineHeight: 1,
            }}
          >
            ✕
          </button>

          <p style={{ color: "#64748b", fontSize: 11, letterSpacing: 2, marginBottom: 6, marginTop: 0 }}>
            {node.kind.toUpperCase().replace("-", " ")}
          </p>
          <h2 style={{ color: "#f1f5f9", margin: "0 0 16px", fontSize: 16, lineHeight: 1.4 }}>
            {node.label}
          </h2>

          {/* Subdomain info */}
          {(node.kind === "subdomain-cf" || node.kind === "subdomain-exp") && (() => {
            const s = ACME_CORP_DATA.subdomains.find((x) => x.id === node.subdomainId);
            if (!s) return null;
            return (
              <div style={{ color: "#94a3b8", fontSize: 13 }}>
                <p style={{ margin: "0 0 8px" }}><strong style={{ color: "#e2e8f0" }}>IP:</strong> {s.ip}</p>
                <p style={{ margin: "0 0 8px" }}><strong style={{ color: "#e2e8f0" }}>Role:</strong> {s.role}</p>
                <p style={{ margin: "0 0 8px" }}>
                  <strong style={{ color: "#e2e8f0" }}>Cloudflare:</strong>{" "}
                  {s.cloudflareProtected ? "🔒 Protected" : "⚠️ Exposed"}
                </p>
                {s.openPorts.length > 0 && (
                  <div style={{ marginTop: 12 }}>
                    <p style={{ margin: "0 0 6px", color: "#e2e8f0", fontWeight: 600 }}>Open Ports</p>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                      {s.openPorts.map((p) => (
                        <span key={p.port} style={{
                          background: "#1e293b",
                          border: "1px solid #334155",
                          borderRadius: 4,
                          padding: "2px 8px",
                          fontSize: 12,
                        }}>
                          {p.port} {p.service}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })()}

          {/* Vuln / email detail */}
          {detail && (
            <div style={{ marginTop: 4 }}>
              <div style={{ marginBottom: 12 }}>
                <SeverityBadge sev={detail.severity} />
              </div>

              <Section title="What's happening">
                {detail.description}
              </Section>
              <Section title="Real-world example">
                {detail.realWorldExample}
              </Section>
              <Section title="How to fix">
                {detail.howToFix}
              </Section>

              {!isFixed ? (
                <motion.button
                  onClick={() => onFix(node)}
                  disabled={!!fixing}
                  whileHover={{ scale: 1.03 }}
                  whileTap={{ scale: 0.97 }}
                  style={{
                    width: "100%",
                    marginTop: 20,
                    padding: "14px 0",
                    borderRadius: 8,
                    border: "none",
                    background: isFix
                      ? "linear-gradient(90deg,#ef4444,#f59e0b,#4ade80)"
                      : "#ef4444",
                    backgroundSize: "200%",
                    color: "#fff",
                    fontWeight: 700,
                    fontSize: 15,
                    letterSpacing: 1.5,
                    cursor: fixing ? "not-allowed" : "pointer",
                    opacity: fixing && !isFix ? 0.5 : 1,
                    transition: "background 0.4s",
                  }}
                >
                  {isFix ? "FIXING..." : "FIX IT"}
                </motion.button>
              ) : (
                <div style={{
                  marginTop: 20,
                  padding: "14px 0",
                  borderRadius: 8,
                  background: "#166534",
                  color: "#4ade80",
                  fontWeight: 700,
                  fontSize: 15,
                  letterSpacing: 1.5,
                  textAlign: "center",
                }}>
                  ✓ FIXED
                </div>
              )}
            </div>
          )}

          {/* Port info */}
          {(node.kind === "port-safe" || node.kind === "port-risky") && (
            <div style={{ color: "#94a3b8", fontSize: 13 }}>
              <p style={{ marginTop: 0 }}>
                {node.kind === "port-risky"
                  ? "⚠️ This port is associated with high-risk services. Verify it is intentionally exposed."
                  : "✓ Standard port. Ensure it is intentionally exposed and patched."}
              </p>
            </div>
          )}

          {/* IP info */}
          {node.kind === "ip" && (
            <p style={{ color: "#94a3b8", fontSize: 13, marginTop: 0 }}>
              Direct IP exposure means attackers can bypass DNS-level protections. Consider routing through Cloudflare.
            </p>
          )}
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function Section({ title, children }: { title: string; children: string }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <p style={{ color: "#94a3b8", fontSize: 11, fontWeight: 700, letterSpacing: 1.5, textTransform: "uppercase", margin: "0 0 4px" }}>
        {title}
      </p>
      <p style={{ color: "#cbd5e1", fontSize: 13, lineHeight: 1.6, margin: 0 }}>
        {children}
      </p>
    </div>
  );
}

// ─── animated counter ─────────────────────────────────────────────────────────

function AnimCounter({ value, color = "#f1f5f9" }: { value: number; color?: string }) {
  const [display, setDisplay] = useState(value);
  const prev = useRef(value);

  useEffect(() => {
    const start = prev.current;
    const end = value;
    if (start === end) return;
    const dur = 600;
    const startTime = performance.now();
    const raf = (t: number) => {
      const p = Math.min((t - startTime) / dur, 1);
      setDisplay(Math.round(start + (end - start) * p));
      if (p < 1) requestAnimationFrame(raf);
      else prev.current = end;
    };
    requestAnimationFrame(raf);
  }, [value]);

  return <span style={{ color, fontVariantNumeric: "tabular-nums" }}>{display}</span>;
}

// ─── particle burst ───────────────────────────────────────────────────────────

interface Particle {
  id: number;
  x: number; y: number;
  vx: number; vy: number;
  color: string;
  life: number;
}

function ParticleBurst({ active, x, y, full }: { active: boolean; x: number; y: number; full?: boolean }) {
  const [particles, setParticles] = useState<Particle[]>([]);
  const animRef = useRef<number>(0);

  useEffect(() => {
    if (!active) return;
    const count = full ? 120 : 30;
    const newP: Particle[] = Array.from({ length: count }, (_, i) => ({
      id: i,
      x: full ? Math.random() * window.innerWidth : x,
      y: full ? Math.random() * window.innerHeight : y,
      vx: (Math.random() - 0.5) * (full ? 6 : 8),
      vy: (Math.random() - 0.5) * (full ? 6 : 8) - (full ? 0 : 2),
      color: ["#4ade80", "#FFD700", "#22d3ee", "#a78bfa"][Math.floor(Math.random() * 4)],
      life: 1,
    }));
    setParticles(newP);

    const start = performance.now();
    const tick = (now: number) => {
      const elapsed = (now - start) / 1000;
      setParticles((prev) =>
        prev.map((p) => ({
          ...p,
          x: p.x + p.vx,
          y: p.y + p.vy,
          vy: p.vy + 0.15,
          life: Math.max(0, 1 - elapsed / 1.5),
        })).filter((p) => p.life > 0)
      );
      if (elapsed < 1.5) animRef.current = requestAnimationFrame(tick);
      else setParticles([]);
    };
    animRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animRef.current);
  }, [active, x, y, full]);

  if (particles.length === 0) return null;
  return (
    <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 200 }}>
      {particles.map((p) => (
        <div key={p.id} style={{
          position: "absolute",
          left: p.x,
          top: p.y,
          width: 6,
          height: 6,
          borderRadius: "50%",
          background: p.color,
          opacity: p.life,
          transform: "translate(-50%,-50%)",
        }} />
      ))}
    </div>
  );
}

// ─── tooltip ──────────────────────────────────────────────────────────────────

interface TooltipState { x: number; y: number; node: GNode }

function Tooltip({ tip }: { tip: TooltipState | null }) {
  if (!tip) return null;
  const oneLiner =
    tip.node.kind === "vuln" ? `${tip.node.vuln!.severity.toUpperCase()} vulnerability` :
    tip.node.kind === "email-warn" ? `${tip.node.emailWarn!.severity.toUpperCase()} email risk` :
    tip.node.kind === "subdomain-cf" ? "Cloudflare-protected" :
    tip.node.kind === "subdomain-exp" ? "Exposed subdomain" :
    tip.node.kind === "ip" ? "Direct IP exposure" :
    tip.node.kind === "port-risky" ? "High-risk open port" :
    tip.node.kind === "port-safe" ? "Open port" :
    tip.node.kind === "root" ? "Root domain" : "";

  return (
    <div style={{
      position: "fixed",
      left: tip.x + 12,
      top: tip.y - 8,
      background: "rgba(10,10,20,0.92)",
      border: "1px solid #334155",
      borderRadius: 8,
      padding: "8px 12px",
      pointerEvents: "none",
      zIndex: 100,
      maxWidth: 280,
    }}>
      <p style={{ color: "#f1f5f9", fontSize: 13, fontWeight: 600, margin: "0 0 2px" }}>{tip.node.label}</p>
      <p style={{ color: "#64748b", fontSize: 11, margin: 0 }}>{oneLiner}</p>
    </div>
  );
}

// ─── main app ─────────────────────────────────────────────────────────────────

export default function App() {
  const [phase, setPhase] = useState<AppPhase>("landing");
  const [scanPhaseIdx, setScanPhaseIdx] = useState(0);
  const [scanProgress, setScanProgress] = useState(0);
  const [fixed, setFixed] = useState<FixedSet>({ vulns: new Set(), emails: new Set() });
  const [fixing, setFixing] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GNode | null>(null);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const [burst, setBurst] = useState<{ active: boolean; x: number; y: number; full: boolean }>({
    active: false, x: 0, y: 0, full: false,
  });
  const [allFixed, setAllFixed] = useState(false);
  const [galaxyPulse, setGalaxyPulse] = useState(false);

  const fgRef = useRef<any>(null);

  const graphData = useMemo(() => buildGraph(fixed), [fixed]);
  const riskScore = useMemo(() => calcRisk(fixed), [fixed]);

  const totalVulns = ACME_CORP_DATA.subdomains.flatMap((s) => s.vulnerabilities).length
    + ACME_CORP_DATA.emailSecurityWarnings.length;
  const fixedCount = fixed.vulns.size + fixed.emails.size;

  // HUD stats
  const openPorts = ACME_CORP_DATA.subdomains
    .filter((s) => !s.cloudflareProtected)
    .reduce((a, s) => a + s.openPorts.length, 0);
  const warnings = totalVulns - fixedCount;

  // ── scan animation ──────────────────────────────────────────────────────────

  function startScan() {
    setPhase("scanning");
    setScanPhaseIdx(0);
    setScanProgress(0);

    let startTime = performance.now();
    const tick = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / SCAN_TOTAL_MS, 1);
      const phaseIdx = Math.min(
        Math.floor((elapsed / SCAN_TOTAL_MS) * SCAN_PHASES.length),
        SCAN_PHASES.length - 1
      );
      setScanProgress(progress);
      setScanPhaseIdx(phaseIdx);
      if (progress < 1) {
        requestAnimationFrame(tick);
      } else {
        setPhase("galaxy");
      }
    };
    requestAnimationFrame(tick);
  }

  // ── fix handler ─────────────────────────────────────────────────────────────

  const handleFix = useCallback((node: GNode) => {
    if (fixing) return;
    setFixing(node.id);

    setTimeout(() => {
      setFixed((prev) => {
        const next: FixedSet = {
          vulns: new Set(prev.vulns),
          emails: new Set(prev.emails),
        };
        if (node.vuln) next.vulns.add(node.vuln.id);
        if (node.emailWarn) next.emails.add(node.emailWarn.id);

        // check all fixed
        const vFixed = next.vulns.size;
        const eFixed = next.emails.size;
        const allVulns = ACME_CORP_DATA.subdomains.flatMap((s) => s.vulnerabilities).length;
        const allEmails = ACME_CORP_DATA.emailSecurityWarnings.length;

        if (vFixed >= allVulns && eFixed >= allEmails) {
          setAllFixed(true);
          setGalaxyPulse(true);
          setTimeout(() => setGalaxyPulse(false), 2000);
          setBurst({ active: true, x: window.innerWidth / 2, y: window.innerHeight / 2, full: true });
          setTimeout(() => setBurst((b) => ({ ...b, active: false })), 2000);
        } else {
          setBurst({ active: true, x: window.innerWidth * 0.65, y: window.innerHeight * 0.5, full: false });
          setTimeout(() => setBurst((b) => ({ ...b, active: false })), 1600);
        }

        return next;
      });
      setFixing(null);
    }, 1500);
  }, [fixing]);

  // ── camera focus ─────────────────────────────────────────────────────────────

  const focusNode = useCallback((node: GNode) => {
    const fg = fgRef.current;
    if (!fg || node.x == null) return;
    const dist = 120;
    const dir = new THREE.Vector3(node.x ?? 0, node.y ?? 0, node.z ?? 0).normalize();
    fg.cameraPosition(
      { x: (node.x ?? 0) + dir.x * dist, y: (node.y ?? 0) + dir.y * dist, z: (node.z ?? 0) + dir.z * dist },
      { x: node.x ?? 0, y: node.y ?? 0, z: node.z ?? 0 },
      800
    );
  }, []);

  // ── node rendering ───────────────────────────────────────────────────────────

  const nodeThreeObject = useCallback((node: GNode) => {
    const isFixed =
      node.vuln ? fixed.vulns.has(node.vuln.id) :
      node.emailWarn ? fixed.emails.has(node.emailWarn.id) : false;

    const color = isFixed ? "#4ade80" : node.color;
    const size = node.val * 0.5;

    let geo: THREE.BufferGeometry;
    if (node.kind === "root") {
      geo = new THREE.OctahedronGeometry(size, 0);
    } else if (node.kind === "vuln" || node.kind === "email-warn") {
      geo = new THREE.IcosahedronGeometry(size, 0);
    } else if (node.kind === "port-safe" || node.kind === "port-risky") {
      geo = new THREE.SphereGeometry(size, 6, 6);
    } else {
      geo = new THREE.SphereGeometry(size, 12, 12);
    }

    const mat = new THREE.MeshLambertMaterial({
      color,
      transparent: node.kind === "vuln" || node.kind === "email-warn",
      opacity: 1,
      emissive: new THREE.Color(color).multiplyScalar(0.4),
    });

    const mesh = new THREE.Mesh(geo, mat);

    // Add a sprite label for important nodes
    if (node.kind === "root" || node.kind === "subdomain-cf" || node.kind === "subdomain-exp") {
      const canvas = document.createElement("canvas");
      canvas.width = 512; canvas.height = 64;
      const ctx = canvas.getContext("2d")!;
      ctx.font = "bold 22px monospace";
      ctx.fillStyle = "#ffffff";
      ctx.textAlign = "center";
      ctx.fillText(node.label.replace("🔒 ", "🔒 "), 256, 42);
      const tex = new THREE.CanvasTexture(canvas);
      const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
      sprite.scale.set(20, 2.5, 1);
      sprite.position.set(0, size + 2, 0);
      mesh.add(sprite);
    }

    return mesh;
  }, [fixed]);

  // Animate vuln/email nodes with sin-wave opacity
  useEffect(() => {
    if (phase !== "galaxy") return;
    let raf: number;
    const animate = () => {
      const t = performance.now() / 1000;
      graphData.nodes.forEach((n) => {
        if (n.kind === "vuln" || n.kind === "email-warn") {
          const obj = n.__threeObj as THREE.Mesh | undefined;
          if (!obj) return;
          const mat = (obj as THREE.Mesh).material as THREE.MeshLambertMaterial;
          const isFixed =
            n.vuln ? fixed.vulns.has(n.vuln.id) :
            n.emailWarn ? fixed.emails.has(n.emailWarn.id) : false;
          mat.opacity = isFixed ? 1 : 0.5 + 0.5 * Math.sin(t * 2.5 + (n.id.charCodeAt(0) ?? 0));
        }
      });
      raf = requestAnimationFrame(animate);
    };
    raf = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(raf);
  }, [phase, graphData.nodes, fixed]);

  // ── reset ─────────────────────────────────────────────────────────────────────

  function reset() {
    setFixed({ vulns: new Set(), emails: new Set() });
    setSelectedNode(null);
    setAllFixed(false);
    setFixing(null);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────────────────

  return (
    <div style={{
      width: "100vw",
      height: "100vh",
      background: "#0a0a0f",
      overflow: "hidden",
      fontFamily: "'Segoe UI', system-ui, sans-serif",
      position: "relative",
    }}>
      <ParticleBurst active={burst.active} x={burst.x} y={burst.y} full={burst.full} />

      {/* ── LANDING ─────────────────────────────────────────────────────── */}
      <AnimatePresence>
        {phase === "landing" && (
          <motion.div
            key="landing"
            initial={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: "absolute",
              inset: 0,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              gap: 16,
              zIndex: 20,
            }}
          >
            {/* starfield dots */}
            <div style={{ position: "absolute", inset: 0, overflow: "hidden", pointerEvents: "none" }}>
              {Array.from({ length: 80 }).map((_, i) => (
                <motion.div
                  key={i}
                  animate={{ opacity: [0.2, 1, 0.2] }}
                  transition={{ duration: 2 + Math.random() * 3, repeat: Infinity, delay: Math.random() * 4 }}
                  style={{
                    position: "absolute",
                    width: Math.random() * 3 + 1,
                    height: Math.random() * 3 + 1,
                    borderRadius: "50%",
                    background: "#fff",
                    left: `${Math.random() * 100}%`,
                    top: `${Math.random() * 100}%`,
                  }}
                />
              ))}
            </div>

            <motion.h1
              initial={{ y: 40, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.2 }}
              style={{
                color: "#FFD700",
                fontSize: "clamp(28px, 5vw, 52px)",
                fontWeight: 700,
                letterSpacing: -1,
                margin: 0,
                textShadow: "0 0 40px rgba(255,215,0,0.5)",
              }}
            >
              ACME Corp Attack Surface
            </motion.h1>

            <motion.p
              initial={{ y: 30, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.35 }}
              style={{ color: "#64748b", fontSize: 16, margin: 0 }}
            >
              A fictional target for learning real security
            </motion.p>

            <motion.button
              initial={{ y: 30, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.5 }}
              whileHover={{ scale: 1.06, boxShadow: "0 0 40px rgba(239,68,68,0.6)" }}
              whileTap={{ scale: 0.97 }}
              onClick={startScan}
              style={{
                marginTop: 24,
                padding: "16px 48px",
                background: "linear-gradient(135deg, #ef4444, #b91c1c)",
                border: "none",
                borderRadius: 12,
                color: "#fff",
                fontSize: 18,
                fontWeight: 700,
                letterSpacing: 3,
                cursor: "pointer",
                boxShadow: "0 0 20px rgba(239,68,68,0.3)",
              }}
            >
              SCAN ACME CORP
            </motion.button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── SCAN ANIMATION ──────────────────────────────────────────────── */}
      <AnimatePresence>
        {phase === "scanning" && (
          <motion.div
            key="scan"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: "absolute",
              inset: 0,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              gap: 24,
              zIndex: 20,
              background: "#0a0a0f",
            }}
          >
            <p style={{ color: "#4ade80", fontSize: 13, letterSpacing: 3, margin: 0, fontWeight: 600 }}>
              SCANNING
            </p>
            <h2 style={{ color: "#f1f5f9", fontSize: 22, margin: 0, fontWeight: 400 }}>
              {SCAN_PHASES[scanPhaseIdx]}
            </h2>

            {/* Phase dots */}
            <div style={{ display: "flex", gap: 8 }}>
              {SCAN_PHASES.map((ph, i) => (
                <motion.div
                  key={ph}
                  animate={{ background: i <= scanPhaseIdx ? "#4ade80" : "#1e293b" }}
                  style={{ width: 32, height: 4, borderRadius: 2 }}
                />
              ))}
            </div>

            {/* Progress bar */}
            <div style={{ width: 360, height: 4, background: "#1e293b", borderRadius: 2, overflow: "hidden" }}>
              <motion.div
                style={{ height: "100%", background: "#4ade80", width: `${scanProgress * 100}%` }}
              />
            </div>

            {/* Fake log lines */}
            <div style={{ color: "#334155", fontSize: 12, fontFamily: "monospace", textAlign: "left", width: 360 }}>
              {ACME_CORP_DATA.subdomains.slice(0, (scanPhaseIdx + 1) * 8).map((s) => (
                <div key={s.id} style={{ color: "#22d3ee", marginBottom: 2 }}>
                  {">"} Found {s.fqdn} → {s.ip}
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── GALAXY ──────────────────────────────────────────────────────── */}
      {phase === "galaxy" && (
        <>
          {/* 3D graph */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            style={{
              position: "absolute",
              inset: 0,
              outline: galaxyPulse ? "3px solid #4ade80" : "none",
              transition: "outline 0.3s",
            }}
          >
            <ForceGraph3D
              ref={fgRef}
              graphData={graphData as any}
              backgroundColor="#0a0a0f"
              nodeThreeObject={nodeThreeObject as any}
              nodeThreeObjectExtend={false}
              linkColor={() => "#1e3a5f"}
              linkOpacity={0.4}
              linkWidth={0.5}
              d3AlphaDecay={0.02}
              d3VelocityDecay={0.3}
              onEngineStop={() => {
                // apply strong central gravity via d3 manyBody after engine ready
                const fg = fgRef.current;
                if (!fg) return;
                fg.d3Force("charge")?.strength(-80);
                fg.d3Force("link")?.distance(80);
              }}
              postProcessingComposer={(composer: any) => {
                // Add UnrealBloomPass for glow effect
                import("three/examples/jsm/postprocessing/UnrealBloomPass.js").then(({ UnrealBloomPass }) => {
                  const bloomPass = new UnrealBloomPass(
                    new THREE.Vector2(window.innerWidth, window.innerHeight),
                    0.8,  // strength
                    0.4,  // radius
                    0.1   // threshold
                  );
                  composer.addPass(bloomPass);
                });
              }}
              onNodeHover={(node: any, _prev: any, event: any) => {
                if (!node) { setTooltip(null); return; }
                const e = event as MouseEvent;
                setTooltip({ x: e.clientX, y: e.clientY, node: node as GNode });
              }}
              onNodeClick={(node: any) => {
                const n = node as GNode;
                setSelectedNode(n);
                focusNode(n);
              }}
              onBackgroundClick={() => setSelectedNode(null)}
            />
          </motion.div>

          {/* Tooltip */}
          <Tooltip tip={tooltip} />

          {/* ── HUD top-right ───────────────────────────────────────────── */}
          <motion.div
            initial={{ x: 120, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ delay: 0.3 }}
            style={{
              position: "fixed",
              top: 20,
              right: selectedNode ? 400 : 20,
              background: "rgba(10,10,20,0.85)",
              border: "1px solid #1e293b",
              borderRadius: 12,
              padding: "16px 20px",
              zIndex: 40,
              minWidth: 180,
              transition: "right 0.4s ease",
            }}
          >
            <p style={{ color: "#64748b", fontSize: 10, letterSpacing: 2, margin: "0 0 12px", fontWeight: 700 }}>
              ACME CORP / LIVE
            </p>
            <Stat label="Subdomains" value={ACME_CORP_DATA.subdomains.length} />
            <Stat label="Exposed IPs" value={ACME_CORP_DATA.subdomains.filter((s) => !s.cloudflareProtected).length} />
            <Stat label="Open Ports" value={openPorts} />
            <Stat label="Warnings" value={warnings} color={warnings > 0 ? "#ef4444" : "#4ade80"} />

            <div style={{ marginTop: 14, paddingTop: 14, borderTop: "1px solid #1e293b" }}>
              <p style={{ color: "#64748b", fontSize: 10, letterSpacing: 2, margin: "0 0 4px", fontWeight: 700 }}>
                RISK SCORE
              </p>
              <p style={{ margin: 0, fontSize: 36, fontWeight: 800, lineHeight: 1 }}>
                <AnimCounter value={riskScore} color={riskColor(riskScore)} />
                <span style={{ color: "#334155", fontSize: 18 }}>/100</span>
              </p>
            </div>
          </motion.div>

          {/* ── All-fixed banner ────────────────────────────────────────── */}
          <AnimatePresence>
            {allFixed && (
              <motion.div
                initial={{ y: -80 }}
                animate={{ y: 0 }}
                exit={{ y: -80 }}
                style={{
                  position: "fixed",
                  top: 0,
                  left: 0,
                  right: 0,
                  textAlign: "center",
                  padding: "18px 0",
                  background: "linear-gradient(90deg,#14532d,#166534,#14532d)",
                  color: "#4ade80",
                  fontWeight: 800,
                  fontSize: 22,
                  letterSpacing: 6,
                  zIndex: 60,
                  borderBottom: "2px solid #4ade80",
                  textShadow: "0 0 20px rgba(74,222,128,0.8)",
                }}
              >
                ACME CORP: SECURED
              </motion.div>
            )}
          </AnimatePresence>

          {/* ── Detail panel ────────────────────────────────────────────── */}
          <DetailPanel
            node={selectedNode}
            onClose={() => setSelectedNode(null)}
            onFix={handleFix}
            fixed={fixed}
            fixing={fixing}
          />

          {/* ── Bottom bar ──────────────────────────────────────────────── */}
          <motion.div
            initial={{ y: 60, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 0.5 }}
            style={{
              position: "fixed",
              bottom: 20,
              left: "50%",
              transform: "translateX(-50%)",
              display: "flex",
              gap: 12,
              zIndex: 40,
            }}
          >
            <BottomBtn onClick={reset} label="RESET ACME" color="#ef4444" />
            <BottomBtn onClick={() => { reset(); startScan(); }} label="SCAN AGAIN" color="#22d3ee" />
          </motion.div>
        </>
      )}
    </div>
  );
}

function Stat({ label, value, color = "#f1f5f9" }: { label: string; value: number; color?: string }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6, gap: 24 }}>
      <span style={{ color: "#64748b", fontSize: 12 }}>{label}</span>
      <AnimCounter value={value} color={color} />
    </div>
  );
}

function BottomBtn({ label, color, onClick }: { label: string; color: string; onClick: () => void }) {
  return (
    <motion.button
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      onClick={onClick}
      style={{
        padding: "10px 24px",
        background: "rgba(10,10,20,0.9)",
        border: `1px solid ${color}`,
        borderRadius: 8,
        color,
        fontSize: 12,
        fontWeight: 700,
        letterSpacing: 2,
        cursor: "pointer",
      }}
    >
      {label}
    </motion.button>
  );
}
