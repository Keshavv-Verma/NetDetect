"""
NetDetect Design System & Stylesheet
Professional SOC Dark-First Cyber Interface
"""

NETDETECT_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

:root {
    --nd-bg-base:        #09090b;
    --nd-bg-surface:     #121215;
    --nd-bg-card:        #18181b;
    --nd-bg-elevated:    #222226;
    --nd-bg-hover:       #2b2b32;
    
    --nd-border-subtle:  rgba(255, 255, 255, 0.08);
    --nd-border-card:    rgba(255, 255, 255, 0.14);
    --nd-border-active:  rgba(255, 255, 255, 0.35);
    
    --nd-cyan:           #f4f4f5;
    --nd-cyan-subtle:    rgba(255, 255, 255, 0.08);
    --nd-cyan-glow:      rgba(255, 255, 255, 0.15);
    
    --nd-indigo:         #a1a1aa;
    --nd-indigo-subtle:  rgba(255, 255, 255, 0.06);
    
    --nd-blue:           #d4d4d8;
    --nd-blue-subtle:    rgba(255, 255, 255, 0.06);
    
    --nd-emerald:        #10b981;
    --nd-emerald-subtle: rgba(16, 185, 129, 0.12);
    
    --nd-amber:          #f59e0b;
    --nd-amber-subtle:   rgba(245, 158, 11, 0.12);
    
    --nd-rose:           #f43f5e;
    --nd-rose-subtle:    rgba(244, 63, 94, 0.14);
    
    --nd-text-primary:   #fafafa;
    --nd-text-secondary: #a1a1aa;
    --nd-text-muted:     #71717a;
    --nd-text-dim:       #52525b;
    
    --nd-font-sans:      'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    --nd-font-mono:      'JetBrains Mono', 'Space Mono', Consolas, monospace;
}

/* Global Reset & Base */
html, body, [class*="css"] {
    background-color: var(--nd-bg-base) !important;
    color: var(--nd-text-primary) !important;
    font-family: var(--nd-font-sans) !important;
    letter-spacing: -0.01em;
}

/* Streamlit Chrome Cleansing */
#MainMenu, 
footer, 
[data-testid="stDeployButton"], 
.stDeployButton, 
[data-testid="stAppDeployButton"], 
.stAppDeployButton,
[data-testid="stToolbarActions"],
.stToolbarActions,
[data-testid="stDecoration"] {
    display: none !important;
    visibility: hidden !important;
    opacity: 0 !important;
    height: 0 !important;
    width: 0 !important;
    pointer-events: none !important;
}

header[data-testid="stHeader"] {
    background: transparent !important;
    backdrop-filter: none !important;
    -webkit-backdrop-filter: none !important;
    height: 0 !important;
    min-height: 0 !important;
    padding: 0 !important;
    margin: 0 !important;
    border: none !important;
    box-shadow: none !important;
    pointer-events: none !important;
    z-index: 100 !important;
}
header[data-testid="stHeader"] * {
    pointer-events: auto !important;
}

[data-testid="stSidebarCollapsedControl"] {
    z-index: 1000000 !important;
}

[data-testid="stExpandSidebarButton"] {
    position: fixed !important;
    top: 14px !important;
    left: 14px !important;
    background: var(--nd-bg-card) !important;
    border: 1px solid var(--nd-border-card) !important;
    border-radius: 8px !important;
    padding: 6px !important;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.4) !important;
    transition: all 0.2s ease !important;
    z-index: 1000000 !important;
}
[data-testid="stExpandSidebarButton"]:hover {
    background: var(--nd-bg-elevated) !important;
    border-color: rgba(255, 255, 255, 0.35) !important;
    box-shadow: 0 0 12px rgba(255, 255, 255, 0.1) !important;
}
[data-testid="stExpandSidebarButton"] svg {
    fill: var(--nd-text-primary) !important;
}

.block-container {
    padding-top: 1.8rem !important;
    padding-bottom: 2.5rem !important;
    max-width: 1440px !important;
}

/* Sidebar Custom Styling */
[data-testid="stSidebar"] {
    background-color: var(--nd-bg-surface) !important;
    border-right: 1px solid var(--nd-border-card) !important;
    box-shadow: 4px 0 24px rgba(0, 0, 0, 0.3) !important;
}
[data-testid="stSidebar"] * {
    color: var(--nd-text-primary) !important;
}
[data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] button {
    background: var(--nd-bg-card) !important;
    border: 1px solid var(--nd-border-card) !important;
    border-radius: 6px !important;
    color: var(--nd-text-secondary) !important;
    transition: all 0.2s ease;
}
[data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] button:hover {
    color: var(--nd-text-primary) !important;
    border-color: rgba(255, 255, 255, 0.3) !important;
}

/* Radio Group / Navigation Pills in Sidebar */
[data-testid="stSidebar"] [data-testid="stRadio"] > div {
    gap: 6px !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label {
    background: var(--nd-bg-card) !important;
    border: 1px solid var(--nd-border-subtle) !important;
    border-radius: 8px !important;
    padding: 10px 14px !important;
    margin-bottom: 2px !important;
    cursor: pointer !important;
    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
    display: flex !important;
    align-items: center !important;
}
/* Hide circular radio bullet for a sleek navigation menu pill */
[data-testid="stSidebar"] [data-testid="stRadio"] label > div:first-child {
    display: none !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
    background: var(--nd-bg-elevated) !important;
    border-color: rgba(255, 255, 255, 0.25) !important;
    transform: translateX(2px) !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-checked="true"],
[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
    background: #27272c !important;
    border-color: rgba(255, 255, 255, 0.25) !important;
    box-shadow: inset 3px 0 0 #fafafa, 0 4px 12px rgba(0, 0, 0, 0.35) !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label span,
[data-testid="stSidebar"] [data-testid="stRadio"] label [data-testid="stMarkdownContainer"] p {
    font-size: 0.82rem !important;
    font-weight: 500 !important;
    letter-spacing: 0.01em !important;
    color: var(--nd-text-secondary) !important;
    margin: 0 !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label:hover span,
[data-testid="stSidebar"] [data-testid="stRadio"] label:hover [data-testid="stMarkdownContainer"] p,
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-checked="true"] span,
[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) span,
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-checked="true"] [data-testid="stMarkdownContainer"] p,
[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) [data-testid="stMarkdownContainer"] p {
    color: #ffffff !important;
    font-weight: 600 !important;
}

/* Modern Topbar */
.nd-topbar {
    background: #18181b;
    background: linear-gradient(180deg, #18181b 0%, #121215 100%);
    border: 1px solid var(--nd-border-card);
    border-radius: 12px;
    padding: 1rem 1.6rem;
    margin-bottom: 1.6rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.45);
    position: relative;
    overflow: hidden;
}
.nd-topbar::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, rgba(255, 255, 255, 0.08) 0%, rgba(255, 255, 255, 0.45) 50%, rgba(255, 255, 255, 0.08) 100%);
}
.nd-topbar-brand {
    display: flex;
    align-items: center;
    gap: 1rem;
}
.nd-logo-mark {
    width: 42px;
    height: 42px;
    border-radius: 10px;
    background: #1f1f23;
    border: 1px solid rgba(255, 255, 255, 0.22);
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.4);
    position: relative;
}
.nd-logo-mark svg {
    width: 24px;
    height: 24px;
}
.nd-brand-titles h1 {
    font-family: var(--nd-font-sans) !important;
    font-size: 1.25rem !important;
    font-weight: 700 !important;
    color: var(--nd-text-primary) !important;
    margin: 0 !important;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
    gap: 0.6rem;
}
.nd-brand-titles h1 .nd-highlight {
    color: #ffffff;
}
.nd-brand-titles p {
    font-family: var(--nd-font-mono) !important;
    font-size: 0.68rem !important;
    color: var(--nd-text-muted) !important;
    margin: 2px 0 0 !important;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}
.nd-topbar-telemetry {
    display: flex;
    align-items: center;
    gap: 1.2rem;
}
.nd-telemetry-pill {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.4rem 0.85rem;
    background: rgba(18, 18, 21, 0.85);
    border: 1px solid var(--nd-border-card);
    border-radius: 20px;
    font-family: var(--nd-font-mono);
    font-size: 0.72rem;
    letter-spacing: 0.04em;
    color: var(--nd-text-secondary);
}
.nd-telemetry-pill-view {
    display: none;
}
@media (min-width: 860px) {
    .nd-telemetry-pill-view {
        display: flex;
    }
}
.nd-status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--nd-emerald);
    box-shadow: 0 0 8px var(--nd-emerald);
}
.nd-status-dot.active {
    animation: nd-dot-pulse 1.8s infinite;
}
.nd-status-dot.warning {
    background: var(--nd-amber);
    box-shadow: 0 0 8px var(--nd-amber);
}
.nd-status-dot.danger {
    background: var(--nd-rose);
    box-shadow: 0 0 8px var(--nd-rose);
}
@keyframes nd-dot-pulse {
    0% { transform: scale(0.95); opacity: 0.8; }
    50% { transform: scale(1.2); opacity: 1; }
    100% { transform: scale(0.95); opacity: 0.8; }
}

/* Page Header System */
.nd-page-header {
    margin-bottom: 1.6rem;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    border-bottom: 1px solid var(--nd-border-subtle);
    padding-bottom: 1rem;
}
.nd-page-title {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--nd-text-primary);
    margin: 0 0 0.3rem 0;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
    gap: 0.6rem;
}
.nd-page-subtitle {
    font-size: 0.82rem;
    color: var(--nd-text-secondary);
    margin: 0;
}
.nd-page-badge {
    font-family: var(--nd-font-mono);
    font-size: 0.68rem;
    padding: 0.25rem 0.65rem;
    border-radius: 6px;
    background: var(--nd-bg-card);
    border: 1px solid var(--nd-border-card);
    color: var(--nd-text-muted);
    letter-spacing: 0.05em;
    text-transform: uppercase;
}

/* Unified Card Component & Streamlit Container Support */
.nd-card,
[data-testid="stVerticalBlockBorderWrapper"] {
    background: var(--nd-bg-card) !important;
    border: 1px solid var(--nd-border-card) !important;
    border-radius: 12px !important;
    padding: 1.2rem 1.4rem !important;
    margin-bottom: 1.2rem !important;
    position: relative !important;
    box-shadow: 0 4px 16px -2px rgba(0, 0, 0, 0.35) !important;
    transition: border-color 0.2s ease, box-shadow 0.2s ease !important;
}
.nd-card:hover,
[data-testid="stVerticalBlockBorderWrapper"]:hover {
    border-color: rgba(255, 255, 255, 0.25) !important;
}
.nd-card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
    padding-bottom: 0.65rem;
    border-bottom: 1px solid var(--nd-border-subtle);
}
.nd-card-title {
    font-family: var(--nd-font-mono);
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--nd-text-secondary);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}
.nd-card-title span.icon {
    color: #d4d4d8;
    font-size: 0.95rem;
}
.nd-card-action {
    font-family: var(--nd-font-mono);
    font-size: 0.7rem;
    color: #a1a1aa;
}

/* Metric / Stat Card System */
.nd-metric-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 1.4rem;
}
@media (max-width: 1024px) {
    .nd-metric-grid { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 640px) {
    .nd-metric-grid { grid-template-columns: 1fr; }
}

.nd-stat-card {
    background: var(--nd-bg-card);
    border: 1px solid var(--nd-border-card);
    border-radius: 10px;
    padding: 1.1rem 1.3rem;
    position: relative;
    overflow: hidden;
    transition: transform 0.2s ease, border-color 0.2s ease;
}
.nd-stat-card:hover {
    transform: translateY(-2px);
    border-color: rgba(255, 255, 255, 0.3);
}
.nd-stat-card::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 2px;
}
.nd-stat-card.cyan::after    { background: #d4d4d8; }
.nd-stat-card.indigo::after  { background: #71717a; }
.nd-stat-card.emerald::after { background: var(--nd-emerald); }
.nd-stat-card.amber::after   { background: var(--nd-amber); }
.nd-stat-card.rose::after    { background: var(--nd-rose); }

.nd-stat-label {
    font-family: var(--nd-font-mono);
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--nd-text-muted);
    margin-bottom: 0.4rem;
}
.nd-stat-value {
    font-family: var(--nd-font-mono);
    font-size: 1.85rem;
    font-weight: 700;
    color: var(--nd-text-primary);
    line-height: 1.1;
    margin-bottom: 0.3rem;
}
.nd-stat-value.cyan    { color: #fafafa; }
.nd-stat-value.indigo  { color: #d4d4d8; }
.nd-stat-value.emerald { color: var(--nd-emerald); }
.nd-stat-value.amber   { color: var(--nd-amber); }
.nd-stat-value.rose    { color: var(--nd-rose); }

.nd-stat-sub {
    font-size: 0.72rem;
    color: var(--nd-text-secondary);
    display: flex;
    align-items: center;
    gap: 0.35rem;
}
.nd-stat-icon {
    position: absolute;
    top: 1rem; right: 1.1rem;
    font-size: 1.3rem;
    opacity: 0.25;
}

/* Verdict Hero Panel */
.nd-verdict-banner {
    background: linear-gradient(135deg, #18181b 0%, #121215 100%);
    border: 1px solid var(--nd-border-card);
    border-radius: 12px;
    padding: 1.6rem 2rem;
    margin-bottom: 1.4rem;
    position: relative;
    overflow: hidden;
}
.nd-verdict-banner.danger {
    border-color: rgba(244, 63, 94, 0.4);
    box-shadow: 0 0 24px rgba(244, 63, 94, 0.12);
}
.nd-verdict-banner.safe {
    border-color: rgba(16, 185, 129, 0.35);
    box-shadow: 0 0 24px rgba(16, 185, 129, 0.08);
}
.nd-verdict-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.5rem 1.2rem;
    border-radius: 8px;
    font-family: var(--nd-font-mono);
    font-size: 1rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    margin-bottom: 0.8rem;
}
.nd-verdict-badge.safe {
    background: var(--nd-emerald-subtle);
    color: var(--nd-emerald);
    border: 1px solid rgba(16, 185, 129, 0.4);
}
.nd-verdict-badge.danger {
    background: var(--nd-rose-subtle);
    color: var(--nd-rose);
    border: 1px solid rgba(244, 63, 94, 0.5);
    animation: nd-threat-pulse 2s infinite;
}
@keyframes nd-threat-pulse {
    0%, 100% { box-shadow: 0 0 4px rgba(244, 63, 94, 0.2); }
    50% { box-shadow: 0 0 16px rgba(244, 63, 94, 0.4); }
}

.nd-analyst-box {
    background: rgba(18, 18, 21, 0.8);
    border-left: 3px solid #71717a;
    border-radius: 0 8px 8px 0;
    padding: 0.9rem 1.3rem;
    font-size: 0.85rem;
    color: var(--nd-text-secondary);
    margin-top: 1rem;
    line-height: 1.6;
}
.nd-analyst-box b {
    color: var(--nd-text-primary);
}

/* Pipeline Progress Steps */
.nd-pipeline-wrap {
    background: var(--nd-bg-card);
    border: 1px solid var(--nd-border-card);
    border-radius: 12px;
    padding: 1.2rem 1.6rem;
    margin-bottom: 1.4rem;
}
.nd-pipeline-steps {
    display: flex;
    justify-content: space-between;
    position: relative;
    margin: 1rem 0 0.5rem;
}
.nd-pipeline-step {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.4rem;
    position: relative;
    z-index: 2;
    flex: 1;
}
.nd-step-circle {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    background: var(--nd-bg-elevated);
    border: 1px solid var(--nd-border-card);
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--nd-font-mono);
    font-size: 0.72rem;
    color: var(--nd-text-muted);
}
.nd-step-circle.done {
    background: var(--nd-emerald-subtle);
    border-color: var(--nd-emerald);
    color: var(--nd-emerald);
}
.nd-step-circle.active {
    background: rgba(255, 255, 255, 0.08);
    border-color: rgba(255, 255, 255, 0.35);
    color: #fafafa;
    box-shadow: 0 0 10px rgba(255, 255, 255, 0.1);
}
.nd-step-label {
    font-family: var(--nd-font-mono);
    font-size: 0.65rem;
    color: var(--nd-text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    text-align: center;
}

/* Native Live Pulse Strip */
.nd-pulse-container {
    background: var(--nd-bg-card);
    border: 1px solid var(--nd-border-card);
    border-radius: 10px;
    padding: 0.9rem 1.2rem;
    margin-bottom: 1.2rem;
}
.nd-pulse-label-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-family: var(--nd-font-mono);
    font-size: 0.68rem;
    letter-spacing: 0.08em;
    color: var(--nd-text-muted);
    margin-bottom: 0.6rem;
}
.nd-pulse-strip {
    display: flex;
    align-items: flex-end;
    gap: 3px;
    height: 38px;
    overflow-x: hidden;
    padding-top: 4px;
}
.nd-pulse-bar {
    flex: 1;
    min-width: 3px;
    max-width: 14px;
    min-height: 4px;
    border-radius: 2px 2px 0 0;
    background: rgba(255, 255, 255, 0.12);
    transition: height 0.25s ease, background-color 0.25s ease;
}
.nd-pulse-bar.info     { background: #a1a1aa; }
.nd-pulse-bar.low      { background: var(--nd-amber); }
.nd-pulse-bar.high     { background: #f97316; }
.nd-pulse-bar.critical { background: var(--nd-rose); }

/* Table Styling */
.nd-table-wrap {
    border: 1px solid var(--nd-border-card);
    border-radius: 10px;
    overflow: hidden;
    background: var(--nd-bg-card);
}
.nd-table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--nd-font-mono);
    font-size: 0.74rem;
}
.nd-table thead th {
    position: sticky;
    top: 0;
    background: var(--nd-bg-elevated);
    text-align: left;
    padding: 10px 14px;
    color: var(--nd-text-secondary);
    font-weight: 600;
    font-size: 0.68rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    border-bottom: 1px solid var(--nd-border-card);
    z-index: 10;
}
.nd-table tbody td {
    padding: 8px 14px;
    border-bottom: 1px solid var(--nd-border-subtle);
    color: var(--nd-text-secondary);
    font-size: 0.73rem;
}
.nd-table tbody tr:hover td {
    background: rgba(255, 255, 255, 0.02);
}
.nd-table tbody tr.is-attack td {
    color: var(--nd-text-primary);
}
.nd-table tbody tr.is-attack {
    background: rgba(244, 63, 94, 0.06);
}

/* Severity and Status Badges */
.nd-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: 4px;
    font-family: var(--nd-font-mono);
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}
.nd-badge.safe     { background: var(--nd-emerald-subtle); color: var(--nd-emerald); border: 1px solid rgba(16, 185, 129, 0.3); }
.nd-badge.attack   { background: var(--nd-rose-subtle); color: var(--nd-rose); border: 1px solid rgba(244, 63, 94, 0.35); }
.nd-badge.info     { background: rgba(255, 255, 255, 0.08); color: #d4d4d8; border: 1px solid rgba(255, 255, 255, 0.2); }
.nd-badge.warning  { background: var(--nd-amber-subtle); color: var(--nd-amber); border: 1px solid rgba(245, 158, 11, 0.3); }
.nd-badge.neutral  { background: rgba(255, 255, 255, 0.06); color: var(--nd-text-secondary); border: 1px solid var(--nd-border-subtle); }

/* Alert Feed Rows */
.nd-alert-feed {
    max-height: 480px;
    overflow-y: auto;
}
.nd-alert-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--nd-border-subtle);
    font-family: var(--nd-font-mono);
    font-size: 0.74rem;
    transition: background 0.15s ease;
}
.nd-alert-row:hover {
    background: rgba(255, 255, 255, 0.02);
}
.nd-alert-row:last-child {
    border-bottom: none;
}
.nd-alert-cat {
    color: var(--nd-text-primary);
    font-weight: 600;
    width: 70px;
    flex-shrink: 0;
}
.nd-alert-ip {
    color: var(--nd-text-secondary);
    flex: 1;
    font-size: 0.72rem;
}
.nd-alert-time {
    color: var(--nd-text-muted);
    font-size: 0.68rem;
    flex-shrink: 0;
}

/* Callout Box */
.nd-callout {
    background: var(--nd-bg-surface);
    border: 1px solid var(--nd-border-card);
    border-radius: 10px;
    padding: 1.1rem 1.3rem;
    font-size: 0.84rem;
    line-height: 1.6;
    color: var(--nd-text-secondary);
    margin-bottom: 1.2rem;
}
.nd-callout b {
    color: #fafafa;
}

/* Empty State */
.nd-empty-state {
    padding: 48px 24px;
    text-align: center;
    color: var(--nd-text-muted);
    font-family: var(--nd-font-mono);
    font-size: 0.8rem;
}
.nd-empty-icon {
    font-size: 2.2rem;
    margin-bottom: 0.8rem;
    opacity: 0.6;
}
.nd-empty-title {
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--nd-text-secondary);
    margin-bottom: 0.3rem;
}

/* Streamlit Button Restyling */
.stButton > button {
    background: #27272a !important;
    color: #ffffff !important;
    border: 1px solid rgba(255, 255, 255, 0.18) !important;
    border-radius: 8px !important;
    font-family: var(--nd-font-mono) !important;
    font-weight: 600 !important;
    font-size: 0.8rem !important;
    letter-spacing: 0.05em !important;
    text-transform: uppercase !important;
    padding: 0.55rem 1.2rem !important;
    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3) !important;
}
.stButton > button:hover {
    background: #3f3f46 !important;
    border-color: rgba(255, 255, 255, 0.35) !important;
    box-shadow: 0 6px 16px rgba(0, 0, 0, 0.4) !important;
    transform: translateY(-1px) !important;
}
.stButton > button:active {
    transform: translateY(0px) !important;
}
.stButton > button:active {
    transform: translateY(0px) !important;
}

/* Secondary / Stop Button variants */
.nd-stop-btn .stButton > button {
    background: linear-gradient(135deg, #991b1b 0%, var(--nd-rose) 100%) !important;
    border-color: rgba(244, 63, 94, 0.4) !important;
}
.nd-stop-btn .stButton > button:hover {
    box-shadow: 0 6px 16px rgba(244, 63, 94, 0.35) !important;
}

.nd-subtle-btn .stButton > button {
    background: var(--nd-bg-elevated) !important;
    color: var(--nd-text-secondary) !important;
    border: 1px solid var(--nd-border-card) !important;
}
.nd-subtle-btn .stButton > button:hover {
    background: var(--nd-bg-hover) !important;
    color: #ffffff !important;
    border-color: rgba(255, 255, 255, 0.3) !important;
}

.nd-reset-btn .stButton > button {
    background: linear-gradient(135deg, rgba(244, 63, 94, 0.15) 0%, rgba(225, 29, 72, 0.25) 100%) !important;
    color: #fda4af !important;
    border: 1px solid rgba(244, 63, 94, 0.35) !important;
    font-size: 0.75rem !important;
    padding: 0.45rem 0.9rem !important;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3) !important;
}
.nd-reset-btn .stButton > button:hover {
    background: linear-gradient(135deg, rgba(244, 63, 94, 0.3) 0%, rgba(225, 29, 72, 0.45) 100%) !important;
    color: #ffffff !important;
    border-color: var(--nd-rose) !important;
    box-shadow: 0 0 14px rgba(244, 63, 94, 0.35) !important;
}

/* File Uploader Custom Styling */
[data-testid="stFileUploader"] {
    background: var(--nd-bg-surface) !important;
    border: 2px dashed rgba(255, 255, 255, 0.18) !important;
    border-radius: 12px !important;
    padding: 1rem !important;
    transition: border-color 0.25s ease, background 0.25s ease !important;
}
[data-testid="stFileUploader"]:hover {
    border-color: rgba(255, 255, 255, 0.45) !important;
    background: rgba(255, 255, 255, 0.03) !important;
}
[data-testid="stFileUploader"] * {
    color: var(--nd-text-secondary) !important;
}

/* Expander Overrides */
[data-testid="stExpander"] {
    background: var(--nd-bg-surface) !important;
    border: 1px solid var(--nd-border-card) !important;
    border-radius: 10px !important;
    margin-bottom: 0.8rem !important;
}
[data-testid="stExpander"] summary {
    font-family: var(--nd-font-mono) !important;
    font-size: 0.82rem !important;
    color: var(--nd-text-secondary) !important;
    padding: 0.8rem 1rem !important;
}
[data-testid="stExpander"] summary:hover {
    color: #ffffff !important;
}

/* Inputs & Selectboxes */
[data-baseweb="select"] > div {
    background: var(--nd-bg-surface) !important;
    border-color: var(--nd-border-card) !important;
    border-radius: 8px !important;
    color: var(--nd-text-primary) !important;
    font-family: var(--nd-font-mono) !important;
    font-size: 0.82rem !important;
}
[data-baseweb="input"] input {
    background: var(--nd-bg-surface) !important;
    color: var(--nd-text-primary) !important;
    font-family: var(--nd-font-mono) !important;
    font-size: 0.82rem !important;
}

/* Streamlit Tabs Customization */
[data-baseweb="tab-list"] {
    background-color: transparent !important;
    border-bottom: 1px solid var(--nd-border-card) !important;
    gap: 8px !important;
    padding-bottom: 4px !important;
    margin-bottom: 1.2rem !important;
}
[data-baseweb="tab"] {
    background-color: var(--nd-bg-surface) !important;
    border: 1px solid var(--nd-border-subtle) !important;
    border-radius: 8px 8px 0 0 !important;
    color: var(--nd-text-secondary) !important;
    font-family: var(--nd-font-mono) !important;
    font-size: 0.78rem !important;
    padding: 8px 16px !important;
    transition: all 0.2s ease !important;
}
[data-baseweb="tab"]:hover {
    color: #ffffff !important;
    border-color: rgba(255, 255, 255, 0.25) !important;
    background: var(--nd-bg-elevated) !important;
}
[data-baseweb="tab"][aria-selected="true"] {
    background: var(--nd-bg-elevated) !important;
    color: #ffffff !important;
    border-color: rgba(255, 255, 255, 0.35) !important;
    box-shadow: 0 -2px 10px rgba(255, 255, 255, 0.05) !important;
}
[data-baseweb="tab-highlight"] {
    background-color: #fafafa !important;
    height: 2px !important;
}
[data-baseweb="tab-border"] {
    background-color: var(--nd-border-card) !important;
}

/* Monitoring Grid Responsiveness */
.nd-monitoring-grid {
    display: grid;
    grid-template-columns: 1fr 1.6fr;
    gap: 16px;
}
@media (max-width: 960px) {
    .nd-monitoring-grid {
        grid-template-columns: 1fr;
    }
}

/* Verdict Metrics Alignment */
.nd-verdict-metrics {
    text-align: right;
    min-width: 180px;
}
@media (max-width: 768px) {
    .nd-verdict-metrics {
        text-align: left;
        min-width: 100%;
        margin-top: 0.8rem;
    }
}

/* Topbar Responsiveness */
@media (max-width: 680px) {
    .nd-topbar {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.8rem;
        padding: 1rem;
    }
    .nd-topbar-telemetry {
        width: 100%;
        justify-content: space-between;
        gap: 0.4rem;
        flex-wrap: wrap;
    }
    .nd-telemetry-pill {
        font-size: 0.65rem;
        padding: 0.35rem 0.65rem;
    }
}

/* Table Text Alignment */
.nd-table th.num-col, .nd-table td.num-col {
    text-align: right;
}
.nd-table th.center-col, .nd-table td.center-col {
    text-align: center;
}

/* Custom Scrollbar */
::-webkit-scrollbar {
    width: 6px;
    height: 6px;
}
::-webkit-scrollbar-track {
    background: var(--nd-bg-base);
}
::-webkit-scrollbar-thumb {
    background: rgba(255, 255, 255, 0.18);
    border-radius: 3px;
}
::-webkit-scrollbar-thumb:hover {
    background: rgba(255, 255, 255, 0.35);
}
}
</style>
"""
