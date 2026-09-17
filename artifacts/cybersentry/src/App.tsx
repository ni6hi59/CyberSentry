import { type CSSProperties, type ReactNode, useEffect, useMemo, useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  AlertTriangle,
  ArrowUpRight,
  BookOpen,
  ChevronDown,
  Clipboard,
  Clock3,
  ExternalLink,
  FileSearch,
  Globe2,
  History,
  Info,
  LayoutDashboard,
  Link2,
  LoaderCircle,
  Menu,
  PanelLeftClose,
  Plus,
  Radar,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  X,
} from 'lucide-react';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import NotFound from '@/pages/not-found';
import { Route, Switch, useLocation, Router as WouterRouter } from 'wouter';

const queryClient = new QueryClient();

type ScanStatus = 'caution' | 'clear' | 'review';
type Scan = {
  id: number;
  url: string;
  host: string;
  status: ScanStatus;
  score: number;
  scannedAt: string;
  flags: number;
};

const initialScans: Scan[] = [
  { id: 1, url: 'https://support.paypal.com/verify-account', host: 'support.paypal.com', status: 'caution', score: 61, scannedAt: 'Today, 09:42', flags: 3 },
  { id: 2, url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP', host: 'developer.mozilla.org', status: 'clear', score: 94, scannedAt: 'Yesterday, 16:18', flags: 0 },
  { id: 3, url: 'https://accounts-google.security-check.co/login', host: 'accounts-google.security-check.co', status: 'review', score: 28, scannedAt: 'Yesterday, 11:03', flags: 6 },
  { id: 4, url: 'https://www.nytimes.com/interactive/2024', host: 'www.nytimes.com', status: 'clear', score: 97, scannedAt: 'Mon, 14:26', flags: 0 },
];

const statusCopy: Record<ScanStatus, { label: string; detail: string }> = {
  caution: { label: 'Proceed with caution', detail: 'Some signals need a closer look before you open this URL.' },
  clear: { label: 'Looks familiar', detail: 'No major warning signals found in our passive checks.' },
  review: { label: 'High risk signals', detail: 'Several patterns match known social engineering techniques.' },
};

function AppMark() {
  return (
    <div className="app-mark" aria-label="CyberSentry mark">
      <span className="app-mark__orbit" />
      <span className="app-mark__core"><Shield size={17} strokeWidth={2.4} /></span>
    </div>
  );
}

function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <div className={compact ? 'brand brand--compact' : 'brand'}>
      <AppMark />
      {!compact && <div><strong>Cyber<span>Sentry</span></strong><small>URL intelligence, calmly.</small></div>}
    </div>
  );
}

function StatusPill({ status }: { status: ScanStatus }) {
  const Icon = status === 'clear' ? ShieldCheck : status === 'review' ? ShieldAlert : AlertTriangle;
  return (
    <span className={`status-pill status-pill--${status}`} data-testid={`status-pill-${status}`}>
      <Icon size={13} />
      {statusCopy[status].label}
    </span>
  );
}

function ScoreRing({ score, large = false }: { score: number; large?: boolean }) {
  const tone = score >= 80 ? 'clear' : score >= 45 ? 'caution' : 'review';
  return (
    <div className={`score-ring score-ring--${tone} ${large ? 'score-ring--large' : ''}`} style={{ '--score': `${score * 3.6}deg` } as CSSProperties}>
      <div className="score-ring__inside">
        <strong>{score}</strong>
        <span>/ 100</span>
      </div>
    </div>
  );
}

function Sidebar({ active, onNavigate, onNewScan, collapsed, onCollapse }: {
  active: string;
  onNavigate: (view: string) => void;
  onNewScan: () => void;
  collapsed: boolean;
  onCollapse: () => void;
}) {
  const items = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'history', label: 'Scan history', icon: History, count: 12 },
    { id: 'learn', label: 'Learn the signals', icon: BookOpen },
  ];
  return (
    <aside className={`sidebar ${collapsed ? 'sidebar--collapsed' : ''}`}>
      <div className="sidebar__top">
        <Logo compact={collapsed} />
        <button className="icon-button sidebar__collapse" onClick={onCollapse} aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'} data-testid="button-toggle-sidebar">
          {collapsed ? <Menu size={18} /> : <PanelLeftClose size={18} />}
        </button>
      </div>
      {!collapsed && <p className="eyebrow sidebar__eyebrow">Your workspace</p>}
      <nav className="sidebar__nav" aria-label="Primary navigation">
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              className={`sidebar__item ${active === item.id ? 'sidebar__item--active' : ''}`}
              onClick={() => onNavigate(item.id)}
              data-testid={`nav-${item.id}`}
              title={collapsed ? item.label : undefined}
            >
              <Icon size={18} />
              {!collapsed && <><span>{item.label}</span>{item.count && <span className="sidebar__count">{item.count}</span>}</>}
            </button>
          );
        })}
      </nav>
      <button className="sidebar__new" onClick={onNewScan} data-testid="button-sidebar-new-scan" title={collapsed ? 'New inspection' : undefined}>
        <Plus size={16} />
        {!collapsed && <span>New inspection</span>}
      </button>
      <div className="sidebar__bottom">
        {!collapsed && (
          <div className="sidebar__note">
            <div className="sidebar__note-icon"><Sparkles size={16} /></div>
            <div><strong>Stay curious.</strong><p>Every flag is a lesson, not a verdict.</p></div>
          </div>
        )}
        <div className="sidebar__profile">
          <div className="avatar">AR</div>
          {!collapsed && <div><strong>Alex Rivera</strong><span>Personal workspace</span></div>}
          {!collapsed && <ChevronDown size={15} className="sidebar__profile-chevron" />}
        </div>
      </div>
    </aside>
  );
}

function Header({ active, onOpenMobile }: { active: string; onOpenMobile: () => void }) {
  const labels: Record<string, string> = { overview: 'Overview', history: 'Scan history', learn: 'Learn the signals' };
  return (
    <header className="topbar">
      <button className="icon-button mobile-menu" onClick={onOpenMobile} aria-label="Open navigation" data-testid="button-open-navigation"><Menu size={20} /></button>
      <div className="topbar__crumb"><span>Workspace</span><span className="topbar__slash">/</span><strong>{labels[active]}</strong></div>
      <div className="topbar__actions">
        <span className="live-indicator"><i /> Passive mode on</span>
        <button className="help-button" aria-label="About passive mode" data-testid="button-about-passive-mode"><Info size={16} /></button>
      </div>
    </header>
  );
}

function ScanComposer({ value, onChange, onScan, scanning, onPaste }: {
  value: string;
  onChange: (value: string) => void;
  onScan: () => void;
  scanning: boolean;
  onPaste: () => void;
}) {
  return (
    <section className="composer panel">
      <div className="composer__heading">
        <div>
          <span className="section-kicker"><Radar size={14} /> Passive URL inspection</span>
          <h2>Look before you leap.</h2>
          <p>Paste a URL and we’ll examine its signals without opening the page.</p>
        </div>
        <div className="composer__orb"><div className="composer__orb-inner"><Link2 size={24} /></div></div>
      </div>
      <div className="url-form">
        <div className="url-input-wrap">
          <Globe2 size={19} className="url-input-icon" />
          <input
            value={value}
            onChange={(event) => onChange(event.target.value)}
            onKeyDown={(event) => { if (event.key === 'Enter') onScan(); }}
            placeholder="https://example.com/path"
            aria-label="URL to inspect"
            data-testid="input-url"
          />
          {value && <button className="input-clear" onClick={() => onChange('')} aria-label="Clear URL" data-testid="button-clear-url"><X size={16} /></button>}
          <button className="paste-button" onClick={onPaste} data-testid="button-paste-url"><Clipboard size={14} /> Paste</button>
        </div>
        <button className="scan-button" onClick={onScan} disabled={scanning || !value.trim()} data-testid="button-scan-url">
          {scanning ? <LoaderCircle size={18} className="spin" /> : <Search size={18} />}
          {scanning ? 'Inspecting' : 'Inspect URL'}
          <ArrowUpRight size={16} />
        </button>
      </div>
      <div className="composer__meta">
        <span><ShieldCheck size={14} /> No page content loaded</span>
        <span><span className="meta-dot" /> Takes about 3 seconds</span>
        <span className="composer__shortcut">Press <kbd>Enter</kbd> to inspect</span>
      </div>
    </section>
  );
}

function SignalBar({ label, value, tone }: { label: string; value: number; tone: 'good' | 'watch' | 'bad' }) {
  return (
    <div className="signal-row">
      <div className="signal-row__labels"><span>{label}</span><strong>{value}%</strong></div>
      <div className="signal-track"><div className={`signal-fill signal-fill--${tone}`} style={{ width: `${value}%` }} /></div>
    </div>
  );
}

function ResultPanel({ scan, onClear, onLearn }: { scan: Scan; onClear: () => void; onLearn: () => void }) {
  const isRisk = scan.status !== 'clear';
  return (
    <section className="result-section" data-testid="section-scan-result">
      <div className="section-heading section-heading--result">
        <div><span className="eyebrow">Latest inspection</span><h2>Here’s what we found</h2></div>
        <button className="text-button" onClick={onClear} data-testid="button-new-inspection"><Plus size={15} /> New inspection</button>
      </div>
      <div className="result-grid">
        <article className={`result-card result-card--${scan.status}`}>
          <div className="result-card__top">
            <div><StatusPill status={scan.status} /><span className="result-time"><Clock3 size={12} /> Just now</span></div>
            <button className="icon-button" aria-label="Copy inspected URL" onClick={() => navigator.clipboard?.writeText(scan.url)} data-testid="button-copy-result-url"><Clipboard size={16} /></button>
          </div>
          <div className="result-card__url"><span className="url-lock"><Globe2 size={17} /></span><span>{scan.host}</span><span className="result-card__path">{scan.url.replace(`https://${scan.host}`, '')}</span></div>
          <div className="result-card__score">
            <ScoreRing score={scan.score} large />
            <div><h3>{statusCopy[scan.status].label}</h3><p>{statusCopy[scan.status].detail}</p></div>
          </div>
          <div className="result-card__footer"><span><Shield size={14} /> Passive check complete</span><span>Analyzed {scan.scannedAt}</span></div>
        </article>
        <article className="signals-card panel">
          <div className="signals-card__heading"><div><span className="eyebrow">Signal map</span><h3>What shaped the score</h3></div><span className="signal-count">{scan.flags} flags</span></div>
          <div className="signals-list">
            <SignalBar label="Domain familiarity" value={scan.status === 'review' ? 22 : scan.status === 'caution' ? 58 : 93} tone={scan.status === 'clear' ? 'good' : 'watch'} />
            <SignalBar label="Link structure" value={scan.status === 'review' ? 34 : scan.status === 'caution' ? 64 : 96} tone={scan.status === 'review' ? 'bad' : 'watch'} />
            <SignalBar label="Identity signals" value={scan.status === 'review' ? 19 : scan.status === 'caution' ? 71 : 98} tone={scan.status === 'clear' ? 'good' : 'watch'} />
          </div>
          <div className="flag-list">
            {isRisk ? (
              <>
                <div className="flag-item"><span className="flag-icon flag-icon--amber"><AlertTriangle size={14} /></span><div><strong>Unusual redirect language</strong><span>“verify-account” asks for urgency</span></div><ChevronDown size={15} /></div>
                <div className="flag-item"><span className="flag-icon flag-icon--coral"><ShieldAlert size={14} /></span><div><strong>Host does not match the brand</strong><span>Lookalike domains can borrow trust</span></div><ChevronDown size={15} /></div>
              </>
            ) : (
              <div className="positive-note"><ShieldCheck size={17} /><span>No high-confidence warning patterns detected.</span></div>
            )}
          </div>
          <button className="learn-link" onClick={onLearn} data-testid="button-learn-signals">Understand these signals <ArrowUpRight size={15} /></button>
        </article>
      </div>
    </section>
  );
}

function HistoryView({ scans, onSelect }: { scans: Scan[]; onSelect: (scan: Scan) => void }) {
  return (
    <div className="view-stack view-stack--history">
      <div className="page-intro"><span className="eyebrow">Workspace archive</span><h1>Scan history</h1><p>A quiet record of the links you’ve looked at. Nothing opens automatically.</p></div>
      <div className="history-toolbar panel"><div className="history-search"><Search size={16} /><input placeholder="Filter by domain" aria-label="Filter scan history" data-testid="input-filter-history" /></div><span className="history-total">{scans.length} inspections</span></div>
      <div className="history-table panel">
        <div className="history-table__header"><span>Inspected URL</span><span>Result</span><span>Score</span><span>Scanned</span><span /></div>
        {scans.map((scan) => (
          <button className="history-row" key={scan.id} onClick={() => onSelect(scan)} data-testid={`row-scan-${scan.id}`}>
            <span className="history-url"><Globe2 size={15} /><span><strong>{scan.host}</strong><small>{scan.url.replace(`https://${scan.host}`, '') || '/'}</small></span></span>
            <StatusPill status={scan.status} />
            <span className="history-score"><ScoreRing score={scan.score} /><strong>{scan.score}</strong></span>
            <span className="history-date">{scan.scannedAt}</span>
            <ArrowUpRight size={16} className="history-arrow" />
          </button>
        ))}
      </div>
    </div>
  );
}

function LearnView() {
  const lessons = [
    { num: '01', title: 'Read the host, not the headline.', body: 'The most important part of a URL is the registered domain. Everything before it can be made to sound familiar.' },
    { num: '02', title: 'Urgency is a signal.', body: 'Words like verify, suspended, recover, or final notice are often designed to move you faster than your judgment.' },
    { num: '03', title: 'A lock is not a verdict.', body: 'HTTPS protects the connection. It does not prove who owns the website on the other end.' },
  ];
  return (
    <div className="view-stack learn-view" id="learn-section">
      <div className="page-intro"><span className="eyebrow">A small field guide</span><h1>Learn the signals</h1><p>CyberSentry helps you build a better instinct for suspicious links, one calm check at a time.</p></div>
      <div className="learn-hero panel"><div className="learn-hero__mark"><Radar size={34} /></div><div><span className="section-kicker">The 30-second habit</span><h2>Pause. Read. Verify.</h2><p>Before you click a link in a message, inspect the address. A few seconds of attention can reveal a lot.</p></div></div>
      <div className="lesson-list">{lessons.map((lesson) => <article className="lesson-card" key={lesson.num}><span>{lesson.num}</span><div><h3>{lesson.title}</h3><p>{lesson.body}</p></div><ArrowUpRight size={17} /></article>)}</div>
    </div>
  );
}

function Disclaimer({ onLearn }: { onLearn: () => void }) {
  return (
    <footer className="disclaimer">
      <Info size={16} />
      <p><strong>Educational tool, not a guarantee.</strong> CyberSentry uses passive signals to help you make a more informed choice. It does not certify a URL as safe, and it never replaces your judgment.</p>
      <button className="disclaimer__link" onClick={onLearn} data-testid="button-read-methodology">How it works <ArrowUpRight size={14} /></button>
    </footer>
  );
}

function Dashboard() {
  const [active, setActive] = useState('overview');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<Scan | null>(null);
  const [scans, setScans] = useState(initialScans);

  const latestText = useMemo(() => result ? 'Scan complete' : 'Ready when you are', [result]);

  useEffect(() => {
    if (!mobileOpen) return;
    const close = () => setMobileOpen(false);
    window.addEventListener('resize', close);
    return () => window.removeEventListener('resize', close);
  }, [mobileOpen]);

  const inspect = () => {
    if (!url.trim() || scanning) return;
    setScanning(true);
    window.setTimeout(() => {
      const normalized = url.trim().replace(/^http:\/\//, 'https://');
      const host = normalized.replace(/^https?:\/\//, '').split('/')[0] || 'unknown-host';
      const suspicious = /verify|login|secure|account|gift|claim/i.test(normalized);
      const status: ScanStatus = suspicious ? 'caution' : /google|paypal|microsoft/i.test(host) ? 'review' : 'clear';
      const scan: Scan = { id: Date.now(), url: normalized, host, status, score: status === 'clear' ? 91 : status === 'review' ? 32 : 63, scannedAt: 'Just now', flags: status === 'clear' ? 0 : status === 'review' ? 6 : 3 };
      setResult(scan);
      setScans((current) => [scan, ...current].slice(0, 8));
      setScanning(false);
    }, 900);
  };

  const handleNavigate = (view: string) => {
    setActive(view);
    setMobileOpen(false);
    if (view !== 'overview') window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const clearResult = () => { setResult(null); setUrl(''); setActive('overview'); };

  return (
    <div className="cyber-app">
      <div className={`mobile-backdrop ${mobileOpen ? 'mobile-backdrop--visible' : ''}`} onClick={() => setMobileOpen(false)} />
      <div className={mobileOpen ? 'sidebar-shell sidebar-shell--open' : 'sidebar-shell'}>
        <Sidebar active={active} onNavigate={handleNavigate} onNewScan={clearResult} collapsed={sidebarCollapsed} onCollapse={() => setSidebarCollapsed((current) => !current)} />
      </div>
      <main className="main-shell">
        <Header active={active} onOpenMobile={() => setMobileOpen(true)} />
        <div className="main-content">
          {active === 'overview' && (
            <>
              <div className="page-intro page-intro--overview">
                <div><span className="eyebrow">Tuesday, October 08, 2024</span><h1>Good morning, Alex<span className="title-period">.</span></h1><p>Make the next click a more informed one.</p></div>
                <div className="status-summary"><span className="status-summary__dot" /><div><strong>{latestText}</strong><span>Passive inspection engine</span></div></div>
              </div>
              <ScanComposer value={url} onChange={setUrl} onScan={inspect} scanning={scanning} onPaste={() => setUrl('https://support.paypal.com/verify-account')} />
              {result ? <ResultPanel scan={result} onClear={clearResult} onLearn={() => handleNavigate('learn')} /> : (
                <section className="empty-result panel" data-testid="empty-result-state">
                  <div className="empty-result__visual"><div className="empty-result__ring empty-result__ring--one" /><div className="empty-result__ring empty-result__ring--two" /><FileSearch size={25} /></div>
                  <div><span className="eyebrow">Your results live here</span><h2>No URL inspected yet</h2><p>Paste a link above to see its domain, structure, and trust signals laid out clearly.</p></div>
                  <div className="empty-result__tip"><Sparkles size={15} /> Tip: start with a link you’re unsure about.</div>
                </section>
              )}
              <section className="recent-section">
                <div className="section-heading"><div><span className="eyebrow">Your trail</span><h2>Recent inspections</h2></div><button className="text-button" onClick={() => handleNavigate('history')} data-testid="button-view-history">View all <ArrowUpRight size={15} /></button></div>
                <div className="recent-list">
                  {scans.slice(0, 3).map((scan) => (
                    <button className="recent-row" key={scan.id} onClick={() => { setResult(scan); setUrl(scan.url); }} data-testid={`button-recent-scan-${scan.id}`}>
                      <span className="recent-row__site"><span className={`site-favicon site-favicon--${scan.status}`}><Globe2 size={15} /></span><span><strong>{scan.host}</strong><small>{scan.url.replace(`https://${scan.host}`, '') || '/'}</small></span></span>
                      <StatusPill status={scan.status} />
                      <span className="recent-row__score"><ScoreRing score={scan.score} />{scan.score}</span>
                      <span className="recent-row__date">{scan.scannedAt}</span>
                      <ArrowUpRight size={16} className="recent-row__arrow" />
                    </button>
                  ))}
                </div>
              </section>
              <Disclaimer onLearn={() => handleNavigate('learn')} />
            </>
          )}
          {active === 'history' && <HistoryView scans={scans} onSelect={(scan) => { setResult(scan); setUrl(scan.url); setActive('overview'); }} />}
          {active === 'learn' && <LearnView />}
        </div>
      </main>
    </div>
  );
}

function Router() {
  return (
    <RoutedErrorBoundary>
      <Switch>
        <Route path="/" component={Dashboard} />
        <Route component={NotFound} />
      </Switch>
    </RoutedErrorBoundary>
  );
}

function RoutedErrorBoundary({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}>{children}</ErrorBoundary>;
}

function App() {
  useEffect(() => {
    document.documentElement.classList.add('dark');
    return () => document.documentElement.classList.remove('dark');
  }, []);
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;