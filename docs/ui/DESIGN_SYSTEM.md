# ARKA Tactical SOC — Design System Specification

## 1. Aesthetic Vision & Philosophy

ARKA is an autonomous cybersecurity platform. Its visual console reflects a **Tactical Security Operations Center (SOC)**:
- High information density with strict visual clarity.
- Low-distraction dark mode (`#060e20` deep space navy).
- Distinct, multi-modal status communication (icons + text + color, never color alone).
- Zero decorative gimmicks: no playful animations, no AI sparkle marketing tropes.
- Unambiguous security states: `AUTHORIZED`, `DISCOVERED — NOT AUTHORIZED`, `DENIED`, `WAITING FOR APPROVAL`, `VALIDATED`, `HUMAN CONFIRMED`.

---

## 2. Color Palette & Tactical Semantics

| Token | Hex | Usage / Meaning |
|---|---|---|
| `--background` | `#060e20` | Root tactical background (Deep Space Navy) |
| `--surface` | `#0b152b` | Card / Container surface |
| `--surface-elevated` | `#131b2e` | Modals, drawers, tooltips |
| `--border` | `#1e293b` | Structural borders |
| `--border-subtle` | `#172239` | Table row dividers |
| `--cyan-primary` | `#38bdf8` | Primary active accent, telemetry, links |
| `--emerald-authorized` | `#10b981` | Scope authorized, validated findings, active services |
| `--amber-pending` | `#f59e0b` | Gated operator approval, warning, medium risk |
| `--coral-denied` | `#ff716c` | Scope denial, policy block, critical vulnerability |
| `--purple-agent` | `#a855f7` | Multi-agent reasoning, human confirmation |
| `--gray-discovered` | `#94a3b8` | Discovered but unscoped assets |

---

## 3. Typography

- **Headings & Identifiers**: Space Grotesk / Geist Sans (`font-sans`, tracking wide).
- **Security Codes & Telemetry**: JetBrains Mono / Geist Mono (`font-mono`, uppercase badges, hex hashes).

---

## 4. Reusable Component Catalog

1. **`StatusBadge`**:
   - `AUTHORIZED`: Emerald border, shield check icon.
   - `DISCOVERED — NOT AUTHORIZED`: Muted slate border, shield alert icon.
   - `DENIED`: Rose border, ban icon.
   - `WAITING FOR APPROVAL`: Amber border, clock icon, gentle pulse.
   - `EXECUTING`: Cyan border, play icon.
   - `VALIDATED`: Emerald border, check circle icon.
   - `HUMAN CONFIRMED`: Purple border, user check icon.

2. **`RiskBadge`**:
   - `CRITICAL`: Rose background, alert octagon icon.
   - `HIGH`: Orange background, shield alert icon.
   - `MEDIUM`: Amber background, alert triangle icon.
   - `LOW`: Emerald background, info icon.

3. **`EpistemicLadder`**:
   - Visual 5-stage progression widget displaying:
     1. `OBSERVED` (Raw Telemetry)
     2. `CANDIDATE` (Untrusted Hypothesis)
     3. `SUPPORTED` (Corroborated Telemetry)
     4. `VALIDATED` (Deterministic Check Pass)
     5. `HUMAN_CONFIRMED` (Operator Sign-off)

4. **`HaltAgentsModal`**:
   - High-visibility red killswitch dialog allowing instant deterministic termination of all agent reasoning loops and queued tool executions.
