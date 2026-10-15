# Spec 01: Data (conventions, seed data, golden values)

- **Purpose:** Defines every node, edge, property and the exact expected test results.
- **Read this when:** building the seed (T2), writing query or scoring tests (T3, T4, T5, T6), or whenever you need a number. Never recall a number from memory: open this file.

> **File map note:** section numbers (for example "Section 5.6", "G2", "Q-ATTACK") keep the numbering of the original single-file spec. `AGENTS.md` has the index that says which file holds which section.

---

## 4. Conventions

- IDs: `svc-*`, `db-*`, `role-*`, `vuln-*`, `team-*`, `inc-*`, `finding-*`, `act-*`.
- **Edge key** (used in events and UI): `"<src_id>|<REL_TYPE>|<dst_id>"`, e.g. `svc-payments-gateway|ASSUMES_ROLE|role-storage-manager`. Every edge in the graph has an `isolated` boolean property (seeded `false`).
- Semantics: `A -[:DEPENDS_ON]-> B` means **A depends on B**.
  - **Failure propagation** walks edges **backward** (who points at the failing node).
  - **Attacker reach** walks edges **forward**.

---

## 5. Seed Data (exact; transcribe into JSON)

### 5.1 Teams (5)

| id | name | slack_channel | email |
|---|---|---|---|
| team-payments | Payments | #payments-oncall | payments@example.test |
| team-platform | Platform | #platform-oncall | platform@example.test |
| team-commerce | Commerce | #commerce-oncall | commerce@example.test |
| team-experience | Experience | #experience-oncall | experience@example.test |
| team-data | Data | #data-oncall | data@example.test |

### 5.2 Services (20): props `name, tier, customer_facing, internet_exposed, environment="prod", status="HEALTHY"`

| id | name | tier | cf | exposed | owner |
|---|---|---|---|---|---|
| svc-web-portal | Web Portal | 1 | true | true | team-experience |
| svc-mobile-api | Mobile API | 1 | true | true | team-experience |
| svc-admin-portal | Admin Portal | 1 | true | true | team-experience |
| svc-partner-api | Partner API | 1 | true | true | team-experience |
| svc-checkout-ui | Checkout UI | 1 | true | true | team-payments |
| svc-payments-gateway | Payments Gateway | 1 | true | true | team-payments |
| svc-order | Order Service | 2 | false | false | team-commerce |
| svc-billing | Billing Service | 2 | false | false | team-payments |
| svc-inventory | Inventory Service | 2 | false | false | team-commerce |
| svc-catalog | Catalog Service | 2 | false | false | team-commerce |
| svc-user-profile | User Profile Service | 2 | false | false | team-data |
| svc-recommendation | Recommendation Service | 2 | true | false | team-data |
| svc-search | Search Service | 2 | true | false | team-commerce |
| svc-notification | Notification Service | 2 | false | false | team-commerce |
| svc-reporting | Reporting Service | 2 | false | false | team-data |
| svc-auth | Auth Service | 3 | false | false | team-platform |
| svc-config | Config Service | 3 | false | false | team-platform |
| svc-audit-log | Audit Log Service | 3 | false | false | team-platform |
| svc-session-cache | Session Cache | 3 | false | false | team-platform |
| svc-email-worker | Email Worker | 3 | false | false | team-platform |

Customer-facing total = **8** (6 tier-1 + recommendation + search).

### 5.3 Databases (5): props `name, type, contains_pii, region, criticality`

| id | contains_pii | criticality |
|---|---|---|
| db-user-billing | **true** | high |
| db-customer-profile | **true** | high |
| db-orders | false | high |
| db-catalog | false | medium |
| db-analytics | false | low |

(`type="postgres"`, `region="ap-south-1"` for all.)

### 5.4 IAM roles (6): props `name, permission_level, is_admin`

| id | permission_level | is_admin |
|---|---|---|
| role-storage-manager | medium | false |
| role-data-admin | high | **true** |
| role-readonly-analytics | low | false |
| role-app-default | low | false |
| role-billing-writer | medium | false |
| role-support-agent | low | false |

### 5.5 Vulnerabilities (5): props `cve, severity, cvss, exploitable, title`

| id | cve | severity | cvss | exploitable | affects |
|---|---|---|---|---|---|
| vuln-001 | CVE-2026-9901 | critical | 9.8 | true | svc-payments-gateway |
| vuln-002 | CVE-2026-1177 | medium | 5.4 | false | svc-web-portal |
| vuln-003 | CVE-2026-2203 | high | 7.5 | false | svc-search |
| vuln-004 | CVE-2026-3350 | low | 3.1 | false | svc-email-worker |
| vuln-005 | CVE-2026-4418 | high | 8.1 | true | svc-config |

### 5.6 Edges (all get `isolated=false`)

`DEPENDS_ON` (`C` = critical:true, `n` = critical:false). Format `src -> dst [flag]`:

```
svc-web-portal -> svc-auth C        svc-web-portal -> svc-catalog C
svc-web-portal -> svc-search n      svc-web-portal -> svc-recommendation n
svc-web-portal -> svc-checkout-ui C
svc-mobile-api -> svc-auth C        svc-mobile-api -> svc-catalog C
svc-mobile-api -> svc-order C       svc-mobile-api -> svc-user-profile n
svc-mobile-api -> svc-recommendation n
svc-admin-portal -> svc-auth C      svc-admin-portal -> svc-reporting C
svc-admin-portal -> svc-inventory n svc-admin-portal -> svc-user-profile n
svc-partner-api -> svc-auth C       svc-partner-api -> svc-catalog C
svc-partner-api -> svc-order C
svc-checkout-ui -> svc-payments-gateway C
svc-checkout-ui -> svc-order C      svc-checkout-ui -> svc-auth C
svc-payments-gateway -> svc-billing C
svc-payments-gateway -> svc-order C
svc-payments-gateway -> svc-auth C
svc-payments-gateway -> svc-notification n
svc-order -> svc-inventory C        svc-order -> svc-billing C
svc-order -> svc-config C           svc-order -> svc-notification n
svc-billing -> svc-config C         svc-billing -> svc-audit-log n
svc-inventory -> svc-config C       svc-inventory -> svc-catalog n
svc-catalog -> svc-config C         svc-catalog -> svc-session-cache n
svc-user-profile -> svc-auth C      svc-user-profile -> svc-config C
svc-recommendation -> svc-catalog C svc-recommendation -> svc-user-profile n
svc-recommendation -> svc-config n
svc-search -> svc-catalog C         svc-search -> svc-config n
svc-notification -> svc-email-worker C
svc-notification -> svc-config n
svc-reporting -> svc-billing n      svc-reporting -> svc-order n
svc-reporting -> svc-config C
svc-auth -> svc-config C            svc-auth -> svc-session-cache C
svc-auth -> svc-audit-log n
svc-email-worker -> svc-config C
(svc-config, svc-session-cache, svc-audit-log have NO outgoing DEPENDS_ON)
```

`CONNECTS_TO` (props `access`):
```
svc-billing -> db-user-billing rw        svc-user-profile -> db-customer-profile rw
svc-order -> db-orders rw                svc-catalog -> db-catalog rw
svc-reporting -> db-analytics ro         svc-recommendation -> db-analytics ro
```

`ASSUMES_ROLE`:
```
svc-payments-gateway -> role-storage-manager     svc-billing -> role-billing-writer
svc-reporting -> role-readonly-analytics         svc-user-profile -> role-app-default
svc-order -> role-app-default                    svc-admin-portal -> role-support-agent
```

`CAN_ASSUME` (role chaining; **the planted misconfiguration is the first row**):
```
role-storage-manager -> role-data-admin
role-support-agent -> role-readonly-analytics
```

`CAN_ACCESS` (prop `level`):
```
role-data-admin -> db-customer-profile (admin)   role-data-admin -> db-orders (admin)
role-billing-writer -> db-user-billing (write)   role-readonly-analytics -> db-analytics (read)
role-app-default -> db-orders (write)
```

`AFFECTS`: per 5.5. `OWNS`: per owner column in 5.2 (`Team -[:OWNS]-> Service`).

### 5.7 Indexes
`CREATE INDEX FOR (n:Service) ON (n.id)` and the same for Database, IAMRole, Vulnerability, Team, Incident, Finding, Action.

### 5.8 Seed script requirements
`python seed/seed_graph.py [--reset]`. Without `--reset` it uses `MERGE` (idempotent). With `--reset` it deletes the graph and rebuilds. Prints node/edge counts by label/type. Must also assert the DEPENDS_ON subgraph is **acyclic** (fail loudly otherwise; variable-length queries rely on it).

---

## 6. Golden Values (derived from Section 5; tests must assert these)

### G1. Seed counts
20 Service, 5 Database, 6 IAMRole, 5 Vulnerability, 5 Team = **41 entity nodes**. Edges: 49 `DEPENDS_ON` (count the lines in 5.6 to confirm; if your count differs, recount the transcription), 6 `CONNECTS_TO`, 6 `ASSUMES_ROLE`, 2 `CAN_ASSUME`, 5 `CAN_ACCESS`, 5 `AFFECTS`, 20 `OWNS`.

### G2. Attack paths from `svc-payments-gateway` to PII databases (max_hops=6, nothing isolated)
Exactly **2 targets**, ordered by hops:
1. `db-user-billing`, hops **2**, path `[svc-payments-gateway, svc-billing, db-user-billing]`, edge types `[DEPENDS_ON, CONNECTS_TO]`
2. `db-customer-profile`, hops **3**, path `[svc-payments-gateway, role-storage-manager, role-data-admin, db-customer-profile]`, edge types `[ASSUMES_ROLE, CAN_ASSUME, CAN_ACCESS]` (**the hidden path**; no direct service-to-DB edge exists)

### G3. Containment effects
- After `REVOKE_ROLE svc-payments-gateway|role-storage-manager`: targets = `[db-user-billing]` (1 path).
- After `ISOLATE_NODE svc-payments-gateway` (from clean state): targets = `[]` (0 paths).
- After `rollback`, targets return to the G2 result.

### G4. Failure impact of `svc-config` (reverse, max_hops=3)
**17 impacted services** (every service except `svc-config`, `svc-session-cache`, `svc-audit-log`). Customer-facing among them: **8**.

### G5. Failure impact of `db-orders` (max_hops=3, traversing `DEPENDS_ON|CONNECTS_TO`)
**8 impacted services** with min hop distance: `svc-order`:1; `svc-mobile-api`, `svc-partner-api`, `svc-checkout-ui`, `svc-payments-gateway`, `svc-reporting`:2; `svc-web-portal`, `svc-admin-portal`:3. Customer-facing impacted: **6**. Distinct owning teams: **4** (commerce, experience, payments, data).

### G6. Attack paths from `svc-config`: **0 rows** (no outgoing edges).

### G7. Criticality ranking (metric = transitive dependents via DEPENDS_ON, computed in Cypher)
Top-1 `svc-config` (17), top-2 `svc-catalog` (11). Positions 3+ are not asserted (ties).

### G8. Risk scores (formula in Section 8.1, tolerance ±0.003)
- `svc-payments-gateway` (vuln-001): **≈ 0.828**
- `svc-config` (vuln-005): **≈ 0.514**

### G9. Policy outcomes (Section 8.2)
- `propose_containment(REVOKE_ROLE, "svc-payments-gateway|role-storage-manager")` → `AUTO`
- `propose_containment(ISOLATE_NODE, "svc-payments-gateway")` → `APPROVAL_REQUIRED` (tier-1 customer-facing)
- `propose_containment(ISOLATE_NODE, "svc-config")` → `DENIED` (no verified PII attack path)

---

