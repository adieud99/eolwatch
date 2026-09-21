import { useCallback, useEffect, useRef, useState } from 'react'
import VulnerabilityActions from './VulnerabilityActions'
import VulnerabilityWorklist from './VulnerabilityWorklist'
import SbomExplorer from './SbomExplorer'
import AnalysisTargets, { scopeLabel } from './AnalysisTargets'
import AssetEditor from './AssetEditor'
import ManagementWorkspace from './ManagementWorkspace'
import ProjectHub from './ProjectHub'
import LifecycleCatalog from './LifecycleCatalog'

const EMPTY_SUMMARY = {
  assets: 0,
  software_products: 0,
  sbom_documents: 0,
  components: 0,
  dependencies: 0,
  open_cves: 0,
  affected_assets: 0,
  failed_checks_24h: 0,
  lifecycle_risk: { EXPIRED: 0, CRITICAL: 0, WARN: 0, SAFE: 0, UNKNOWN: 0 },
  sbom_quality: { average_score: 0, below_70: 0 },
  urgent_items: [],
  latest_analyses: [],
}

const riskText = { EXPIRED: '지원 종료', CRITICAL: '긴급', WARN: '주의', SAFE: '안전', UNKNOWN: '미확인' }
const typeText = { server: '서버', storage: '스토리지', network: '네트워크', security: '보안장비', vm: '가상머신', cloud: '클라우드', other: '기타' }
const analysisJobText = { QUEUED: '대기', COLLECTING: '수집', SCANNING: '분석', IMPORTING: '저장', SUCCESS: '완료', FAILED: '실패', CANCEL_REQUESTED: '취소 중', CANCELLED: '취소됨' }
const analysisScopeText = { 'ubuntu-dpkg-installed': 'OS · 설치 패키지', 'demo-python-venv': '데모 앱 · Python' }
const comparisonStatusText = { PERSISTENT: '계속 검출', NEW: '새로 검출', NO_LONGER_DETECTED: '재분석 미검출', COMPONENT_REMOVED: '구성요소 제거' }
const vexStatusText = { AFFECTED: '영향 있음', NOT_AFFECTED: '영향 없음', FIXED: '조치 완료', UNDER_INVESTIGATION: '조사 중' }
const activeAnalysisJob = (job) => ['QUEUED', 'COLLECTING', 'SCANNING', 'IMPORTING', 'CANCEL_REQUESTED'].includes(job.status)

async function api(path, options) {
  const headers = new Headers(options?.headers || {})
  const token = localStorage.getItem('eolwatch_token')
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const response = await fetch(`/api${path}`, { ...options, headers })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    const error = new Error(typeof body.detail === 'string' ? body.detail : '요청을 처리하지 못했습니다.')
    error.status = response.status
    throw error
  }
  if (response.status === 204) return null
  return response.json()
}

async function download(path, filename, signal) {
  const token = localStorage.getItem('eolwatch_token')
  const response = await fetch(`/api${path}`, { headers: { Authorization: `Bearer ${token}` }, signal })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(typeof body.detail === 'string' ? body.detail : '보고서를 내려받지 못했습니다.')
  }
  const blob = await response.blob()
  if (signal?.aborted) return
  const url = URL.createObjectURL(blob)
  try {
    const anchor = document.createElement('a')
    anchor.href = url; anchor.download = filename; anchor.click()
  } finally { URL.revokeObjectURL(url) }
}

function Login({ onLogin }) {
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError('')
    try {
      const data = Object.fromEntries(new FormData(event.currentTarget))
      const result = await api('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      localStorage.setItem('eolwatch_token', result.access_token)
      localStorage.setItem('eolwatch_user', JSON.stringify(result.user))
      onLogin(result.user)
    } catch (reason) { setError(reason.message) }
    finally { setBusy(false) }
  }
  return (
    <main className="login-page">
      <section className="login-card">
        <div className="brand login-brand"><span className="brand-mark">E</span><div><strong>EOLWatch</strong><small>Lifecycle Intelligence</small></div></div>
        <span className="eyebrow">SECURE ACCESS</span><h1>인프라 수명주기 관리</h1>
        <p>승인된 운영 계정으로 로그인하세요.</p>
        <form className="vertical-form" onSubmit={submit}>
          <label>아이디<input name="username" autoComplete="username" required /></label>
          <label>비밀번호<input name="password" type="password" autoComplete="current-password" required minLength="8" /></label>
          {error && <p className="form-error">{error}</p>}
          <button className="primary" disabled={busy}>{busy ? '확인 중…' : '로그인'}</button>
        </form>
      </section>
    </main>
  )
}

function RiskBadge({ level }) {
  return <span className={`risk risk-${level.toLowerCase()}`}>{riskText[level] || level}</span>
}

function Metric({ label, value, detail }) {
  return (
    <article className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  )
}

function Overview({ summary, onViewResult, analysisJobs }) {
  const risks = ['EXPIRED', 'CRITICAL', 'WARN', 'SAFE', 'UNKNOWN']
  const maxRisk = Math.max(...risks.map((risk) => summary.lifecycle_risk[risk] || 0), 1)
  const latest = new Map((summary.latest_analyses || []).map((item) => [`${item.asset_id}-${item.scan_scope}`, item]))
  for (const job of analysisJobs) {
    const scope = job.scan_scope || 'ubuntu-dpkg-installed'
    const key = `${job.asset_id}-${scope}`
    const previous = latest.get(key) || { asset_id: job.asset_id, asset_tag: job.asset_tag, asset_name: job.asset_name, scan_scope: scope }
    const requestTime = new Date(job.requested_at).getTime()
    const previousTime = previous.latest_attempt_requested_at ? new Date(previous.latest_attempt_requested_at).getTime() : -Infinity
    if (requestTime < previousTime || (requestTime === previousTime && job.id < previous.latest_attempt_id)) continue
    latest.set(key, { ...previous, latest_attempt_id: job.id, latest_attempt_status: job.status, latest_attempt_requested_at: job.requested_at, latest_attempt_finished_at: job.finished_at, latest_attempt_is_newer: !previous.last_success_at || requestTime > new Date(previous.last_success_at).getTime() })
  }
  return (
    <>
      <section className="metric-grid">
        <Metric label="관리 자산" value={summary.assets} detail={`${summary.software_products}개 인프라 SW`} />
        <Metric label="현재 분석의 미조치 CVE" value={summary.current_inventory?.open_cves ?? '미확인'} detail={summary.current_inventory ? `자산·범위별 마지막 분석 기준 · ${summary.current_inventory.affected_assets}대` : '현재 분석 집계 정보 없음'} />
        <Metric label="누적 미조치 CVE" value={summary.open_cves ?? 0} detail={`전체 SBOM 이력 기준 · ${summary.affected_assets ?? 0}대`} />
        <Metric label="최근 수집 실패" value={summary.failed_checks_24h ?? 0} detail="최근 24시간" />
        <Metric label="SPDX SBOM" value={summary.sbom_documents} detail={`${summary.components}개 구성요소 · 품질 ${summary.sbom_quality.average_score}%`} />
      </section>

      <section className="panel full-panel compare-panel">
        <div className="panel-heading"><div><span className="eyebrow">LATEST ANALYSIS BY SCOPE</span><h2>자산·범위별 최근 분석</h2><small>마지막으로 성공한 분석 당시의 CVE 수입니다. OS와 앱의 분석 범위를 구분하며, 수동 조치 상태와 별도로 표시합니다.</small></div></div>
        <div className="table-wrap"><table aria-label="자산·범위별 최근 분석"><thead><tr><th>자산</th><th>분석 범위</th><th>마지막 성공 분석</th><th>탐지 CVE</th><th>최근 웹 분석 요청</th><th>확인</th></tr></thead><tbody>
          {[...latest.values()].map((item) => <tr key={`${item.asset_id}-${item.scan_scope}`}>
            <td><strong>{item.asset_tag}</strong><small>{item.asset_name}</small></td>
            <td>{analysisScopeText[item.scan_scope] || scopeLabel(item.scan_scope)}</td>
            <td>{item.analysis_run_id ? <><strong>분석 #{item.analysis_run_id} · SBOM #{item.sbom_id}</strong><small>{new Date(item.last_success_at).toLocaleString('ko-KR')}</small></> : '성공한 분석 없음'}</td>
            <td><strong>{item.cve_count == null ? '미확인' : `${item.cve_count}개`}</strong>{item.cve_count === 0 && <small>해당 범위·분석 시점에서 미검출</small>}</td>
            <td>{item.latest_attempt_id ? <><span className={`job job-${item.latest_attempt_status === 'SUCCESS' ? 'success' : item.latest_attempt_status === 'FAILED' ? 'failed' : item.latest_attempt_status === 'CANCELLED' ? 'cancelled' : 'running'}`}>{analysisJobText[item.latest_attempt_status] || item.latest_attempt_status}</span><small>작업 #{item.latest_attempt_id} · 요청 {new Date(item.latest_attempt_requested_at).toLocaleString('ko-KR')}</small>{item.latest_attempt_finished_at && <small>종료 {new Date(item.latest_attempt_finished_at).toLocaleString('ko-KR')}</small>}{item.latest_attempt_is_newer && item.latest_attempt_status !== 'SUCCESS' && <small>{item.analysis_run_id ? item.latest_attempt_status === 'FAILED' ? '최근 재분석에 실패했습니다. 마지막 성공 분석을 표시합니다.' : item.latest_attempt_status === 'CANCELLED' ? '최근 재분석을 취소했습니다. 마지막 성공 분석을 표시합니다.' : item.latest_attempt_status === 'CANCEL_REQUESTED' ? '재분석 취소를 처리 중입니다. 마지막 성공 분석을 표시합니다.' : '재분석 진행 중입니다. 마지막 성공 분석을 표시합니다.' : '완료된 분석 결과가 없습니다.'}</small>}</> : <small>웹 분석 요청 이력 없음</small>}</td>
            <td><button className="table-button" aria-label={`${item.asset_tag} ${analysisScopeText[item.scan_scope] || scopeLabel(item.scan_scope)} 최근 분석 결과 보기`} disabled={!item.sbom_id} onClick={() => onViewResult(item.sbom_id)}>결과 보기</button></td>
          </tr>)}
          {!latest.size && <tr><td colSpan="6" className="empty">아직 분석 이력이 없습니다. 작업 대상에서 서버 분석을 시작하세요.</td></tr>}
        </tbody></table></div>
      </section>

      <section className="split-grid">
        <article className="panel">
          <div className="panel-heading">
            <div><span className="eyebrow">통합 수명주기</span><h2>지원종료 위험 분포</h2></div>
            <span className="subtle">현재 자산 · 제품 · 구성요소 사용 위치</span>
          </div>
          <div className="risk-bars">
            {risks.map((risk) => (
              <div className="bar-row" key={risk}>
                <span>{riskText[risk]}</span>
                <div className="bar-track"><i className={`bar-${risk.toLowerCase()}`} style={{ width: `${(summary.lifecycle_risk[risk] / maxRisk) * 100}%` }} /></div>
                <b>{summary.lifecycle_risk[risk]}</b>
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="panel-heading">
            <div><span className="eyebrow">우선 조치</span><h2>지원종료 임박 항목</h2></div>
          </div>
          {summary.urgent_items.length === 0 ? (
            <p className="empty">아직 위험 항목이 없습니다.</p>
          ) : (
            <div className="urgent-list">
              {summary.urgent_items.slice(0, 6).map((item, index) => (
                <div className="urgent-item" key={`${item.kind}-${item.name}-${index}`}>
                  <div><small>{item.kind}</small><strong>{item.name} <em>{item.version}</em></strong></div>
                  <div className="urgent-risk"><RiskBadge level={item.risk_level} /><small>{item.days_left < 0 ? `${Math.abs(item.days_left)}일 경과` : `${item.days_left}일 남음`}</small></div>
                </div>
              ))}
            </div>
          )}
        </article>
      </section>
    </>
  )
}

function Assets({ assets, sites, onChanged, canEdit, analysisJobs, pendingAssets, onStartAnalysis, focusedAssetId, onViewProjects, onViewCve, onViewSbom, onViewManagement }) {
  const [editing, setEditing] = useState(null)
  const [assetQuery, setAssetQuery] = useState('')
  const [assetStatus, setAssetStatus] = useState('')
  const [assetCriticality, setAssetCriticality] = useState('')
  useEffect(() => { if (focusedAssetId) setEditing(assets.find((asset) => asset.id === focusedAssetId) || null) }, [focusedAssetId])
  const [deadlineAlerts, setDeadlineAlerts] = useState([])
  useEffect(() => { const controller = new AbortController(); api('/assets/deadline-alerts?days=90', { signal: controller.signal }).then((items) => { if (!controller.signal.aborted) setDeadlineAlerts(items) }).catch(() => {}); return () => controller.abort() }, [assets.length])
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  const [csvResult, setCsvResult] = useState(null)
  const [scanScopes, setScanScopes] = useState({})
  async function submit(event) {
    const form = event.currentTarget
    event.preventDefault()
    setError('')
    const data = Object.fromEntries(new FormData(form))
    for (const key of ['site_id', 'manufacturer', 'model', 'site', 'ip_address', 'ssh_username', 'support_end_date', 'lifecycle_source_url', 'building', 'floor', 'room', 'rack', 'rack_position', 'purchase_date', 'purchase_price', 'power_watts', 'power_source', 'warranty_end_date', 'owner_name', 'owner_department']) if (!data[key]) data[key] = null
    if (data.site_id) data.site_id = Number(data.site_id)
    data.monitored = Boolean(data.monitored)
    try {
      await api('/assets', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      form.reset()
      setOpen(false)
      onChanged('자산을 등록했습니다.')
    } catch (reason) { setError(reason.message) }
  }
  async function importCsv(event) {
    const file = event.target.files[0]
    if (!file) return
    setError(''); setCsvResult(null)
    const form = new FormData(); form.append('file', file)
    try {
      const result = await api('/assets/import-csv', { method: 'POST', body: form })
      setCsvResult(result)
      onChanged(`CSV에서 자산 ${result.created}건을 등록했습니다.`)
    } catch (reason) { setError(reason.message) }
    event.target.value = ''
  }
  return (
    <section className="panel full-panel">
      {editing && <AssetEditor key={editing.id} asset={editing} sites={sites} canEdit={canEdit} request={api} onViewCve={onViewCve} onViewSbom={onViewSbom} onViewManagement={onViewManagement} onSaved={(updated) => { setEditing(null); onChanged(updated ? "자산 정보를 저장했습니다." : "사용하지 않는 자산을 삭제했습니다.") }} onClose={() => setEditing(null)} />}
      <div className="panel-heading">
        <div><span className="eyebrow">Infrastructure</span><h2>인프라 자산</h2></div>
        <div className="action-row">
          {canEdit && <label className="file-button">CSV 등록<input type="file" accept=".csv,text/csv" onChange={importCsv} /></label>}
          {canEdit && <button className="primary" onClick={() => setOpen(!open)}>{open ? '닫기' : '+ 자산 등록'}</button>}
        </div>
      </div>
      {csvResult && <div className="inline-result">전체 {csvResult.total_rows}행 · 성공 {csvResult.created} · 실패 {csvResult.failed}{csvResult.errors.map((item) => <small key={item.row}>{item.row}행 {item.asset_tag || '-'}: {item.message}</small>)}</div>}
        {!!deadlineAlerts.length && <section className="asset-alerts" aria-label="자산 만료 알림"><h3>90일 이내 확인 필요</h3><ul>{deadlineAlerts.slice(0, 8).map((item) => <li key={`${item.kind}-${item.asset_id}-${item.date}-${item.reference || ''}`}><strong>{item.asset_name}</strong><span>{item.kind === 'EOL' ? '지원 종료' : item.kind === 'WARRANTY' ? '보증 종료' : item.kind === 'CONTRACT' ? `계약 ${item.reference || ''}` : `CVE ${item.reference || ''}`} · {item.days_left < 0 ? `${Math.abs(item.days_left)}일 경과` : `${item.days_left}일 남음`}</span><small>{item.date}</small></li>)}</ul></section>}
      {open && (
        <form className="asset-form" onSubmit={submit}>
          <label>자산번호<input name="asset_tag" required placeholder="SRV-001" /></label>
          <label>자산명<input name="name" required placeholder="운영 웹 서버" /></label>
          <label>유형<select name="asset_type" defaultValue="server">{Object.entries(typeText).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label>
          <label>제조사<input name="manufacturer" placeholder="Dell" /></label>
          <label>모델<input name="model" placeholder="PowerEdge R740" /></label>
          <label>시리얼 번호<input name="serial_number" placeholder="SN-001" /></label>
          <label>고객 사이트<select name="site_id"><option value="">연결하지 않음</option>{sites.map((site) => <option value={site.id} key={site.id}>{site.customer_name} · {site.name}</option>)}</select></label>
          <label>랙·위치 메모<input name="site" placeholder="A랙 10U" /></label>
          <label>건물<input name="building" placeholder="본관" /></label>
          <label>층<input name="floor" placeholder="3" /></label>
          <label>전산실<input name="room" placeholder="서버실 1" /></label>
          <label>랙 번호<input name="rack" placeholder="B-12" /></label>
          <label>랙 위치<input name="rack_position" placeholder="24U" /></label>
          <label>관리 IP<input name="ip_address" placeholder="10.0.1.11" /></label>
          <label>SSH 계정<input name="ssh_username" placeholder="eolwatch" /></label>
          <label>구매일<input type="date" name="purchase_date" /></label>
          <label>구매가격 (원)<input type="number" min="0" step="0.01" name="purchase_price" /></label>
          <label>전력 사용량 (W)<input type="number" min="0" step="0.1" name="power_watts" /></label>
          <label>전력 데이터 출처<input name="power_source" placeholder="제조사 사양 / 직접 측정" /></label>
          <label>담당자<input name="owner_name" placeholder="홍길동" /></label>
          <label>담당 부서<input name="owner_department" placeholder="인프라 운영팀" /></label>
          <label>운영 상태<select name="operational_status" defaultValue="ACTIVE"><option value="ACTIVE">운영 중</option><option value="STANDBY">예비</option><option value="REPAIR">수리 중</option><option value="RETIRING">폐기 예정</option><option value="RETIRED">폐기 완료</option></select></label>
          <label>서비스 중요도<select name="service_criticality" defaultValue="STANDARD"><option value="LOW">낮음</option><option value="STANDARD">보통</option><option value="HIGH">높음</option><option value="CRITICAL">핵심</option></select></label>
          <label>지원종료일<input type="date" name="support_end_date" /></label>
          <label>근거 URL<input type="url" name="lifecycle_source_url" placeholder="https://..." /></label>
          <label className="checkbox"><input type="checkbox" name="monitored" /> SSH 점검 대상</label>
          {error && <p className="form-error">{error}</p>}
          <button className="primary submit" type="submit">저장</button>
        </form>
      )}
      {!!assets.length && <section className="asset-priority" aria-label="자산 처리 우선순위"><div><h3>처리 우선순위</h3><p>위험 점수와 CVE·지원 종료 상태를 기준으로 먼저 확인할 자산입니다.</p></div><ol>{[...assets].sort((left, right) => (right.risk_score ?? 0) - (left.risk_score ?? 0)).slice(0, 5).map((asset, index) => <li key={asset.id}><strong>{index + 1}. {asset.name}</strong><span>{asset.asset_tag} · {asset.risk_score ?? 0}점 · {asset.priority_level || 'LOW'}</span><small>CVE {asset.vulnerability_count ?? 0}건 · {asset.days_left == null ? 'EOL 미확인' : asset.days_left < 0 ? 'EOL 경과' : `EOL ${asset.days_left}일 후`}</small><button type="button" className="table-button" onClick={() => setEditing(asset)}>자산 보기</button></li>)}</ol></section>}
      <div className="management-search asset-search"><label>자산 검색<input value={assetQuery} maxLength={100} onChange={(event) => setAssetQuery(event.target.value)} placeholder="자산명, 번호, 모델, 시리얼, IP, 위치" /></label><label>운영 상태<select value={assetStatus} onChange={(event) => setAssetStatus(event.target.value)}><option value="">전체 상태</option><option value="ACTIVE">운영 중</option><option value="STANDBY">예비</option><option value="REPAIR">수리 중</option><option value="RETIRING">폐기 예정</option><option value="RETIRED">폐기 완료</option></select></label><label>서비스 중요도<select value={assetCriticality} onChange={(event) => setAssetCriticality(event.target.value)}><option value="">전체 중요도</option><option value="LOW">낮음</option><option value="STANDARD">보통</option><option value="HIGH">높음</option><option value="CRITICAL">핵심</option></select></label></div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>자산번호</th><th>자산</th><th>구분</th><th>모델</th><th>연결 정보</th><th>지원 상태</th><th>점검·분석</th></tr></thead>
          <tbody>
            {assets.filter((asset) => {
              const query = assetQuery.trim().toLowerCase()
              const searchable = [asset.asset_tag, asset.name, asset.model, asset.serial_number, asset.ip_address, asset.site, asset.building, asset.rack, asset.owner_name].filter(Boolean).join(' ').toLowerCase()
              return (!query || searchable.includes(query)) && (!assetStatus || asset.operational_status === assetStatus) && (!assetCriticality || asset.service_criticality === assetCriticality)
            }).map((asset) => {
              const activeJob = analysisJobs.find((job) => job.asset_id === asset.id && activeAnalysisJob(job))
              const pending = pendingAssets.includes(asset.id)
              const unavailable = !asset.monitored || !asset.ip_address || !asset.ssh_username
              return (
              <tr key={asset.id}>
                <td><code>{asset.asset_tag}</code></td>
                <td><strong>{asset.name}</strong><button className="table-button" aria-label={`${asset.asset_tag} 자산 ${canEdit ? '수정' : '상세'}`} onClick={() => setEditing(asset)}>{canEdit ? '수정' : '상세'}</button><button className="table-button" aria-label={`${asset.asset_tag} 프로젝트와 분석 결과`} onClick={() => onViewProjects(asset.id)}>프로젝트·결과</button><small>{[sites.find((site) => site.id === asset.site_id)?.name || asset.site, asset.building, asset.floor && `${asset.floor}층`, asset.rack].filter(Boolean).join(' · ') || '위치 미입력'}</small></td>
                <td>{typeText[asset.asset_type]}</td><td>{asset.manufacturer} {asset.model}</td>
                <td>소프트웨어 {asset.software_count} · SBOM {asset.sbom_count}</td>
                <td><RiskBadge level={asset.risk_level} /> <small>{asset.days_left === null ? '날짜 미입력' : `${asset.days_left}일`}</small><br /><strong>{asset.risk_score ?? 0}점 · {asset.priority_level || 'LOW'}</strong><small>CVE {asset.vulnerability_count ?? 0}건</small></td>
                <td><label>분석 범위<select aria-label={`${asset.asset_tag} 분석 범위`} value={scanScopes[asset.id] || 'ubuntu-dpkg-installed'} disabled={!canEdit || unavailable || pending || Boolean(activeJob)} onChange={(event) => setScanScopes((current) => ({ ...current, [asset.id]: event.target.value }))}>{Object.entries(analysisScopeText).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><div className="action-row"><button className="table-button" disabled={!canEdit || !asset.ip_address || !asset.ssh_username} onClick={async () => {
                  try {
                    const job = await api(`/checks/assets/${asset.id}/run`, { method: 'POST' })
                    onChanged(job.status === 'SUCCESS' ? '인프라 점검을 완료했습니다.' : `점검 실패: ${job.failure_message}`)
                  } catch (reason) { onChanged(reason.message) }
                }}>SSH 점검</button><button className="table-button" aria-label={`${asset.asset_tag} 취약점 분석`} disabled={!canEdit || unavailable || pending || Boolean(activeJob)} title={!canEdit ? '관리자만 분석을 요청할 수 있습니다.' : unavailable ? 'SSH 점검 대상 설정, 관리 IP와 SSH 계정이 필요합니다.' : activeJob ? `분석 작업 #${activeJob.id} 진행 중` : 'SBOM 수집 후 취약점을 분석합니다.'} onClick={() => onStartAnalysis(asset.id, undefined, scanScopes[asset.id] || 'ubuntu-dpkg-installed')}>{pending ? '요청 중…' : activeJob ? `분석 진행 중 · ${analysisJobText[activeJob.status]}` : '취약점 분석'}</button></div>{unavailable && <small>분석에는 점검 대상 설정·IP·SSH 계정이 필요합니다.</small>}</td>
              </tr>
            )})}
            {!assets.filter((asset) => {
              const query = assetQuery.trim().toLowerCase()
              const searchable = [asset.asset_tag, asset.name, asset.model, asset.serial_number, asset.ip_address, asset.site, asset.building, asset.rack, asset.owner_name].filter(Boolean).join(' ').toLowerCase()
              return (!query || searchable.includes(query)) && (!assetStatus || asset.operational_status === assetStatus) && (!assetCriticality || asset.service_criticality === assetCriticality)
            }).length && <tr><td colSpan="7" className="empty">검색 조건에 맞는 자산이 없습니다.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function Organization({ customers, sites, onChanged, canEdit }) {
  const [error, setError] = useState('')
  async function createCustomer(event) {
    const form = event.currentTarget
    event.preventDefault(); setError('')
    try {
      await api('/customers', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.fromEntries(new FormData(form))) })
      form.reset(); onChanged('고객사를 등록했습니다.')
    } catch (reason) { setError(reason.message) }
  }
  async function createSite(event) {
    const form = event.currentTarget
    event.preventDefault(); setError('')
    const data = Object.fromEntries(new FormData(form)); data.customer_id = Number(data.customer_id)
    try {
      await api('/sites', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      form.reset(); onChanged('고객 사이트를 등록했습니다.')
    } catch (reason) { setError(reason.message) }
  }
  return (
    <section className="split-grid">
      <article className="panel">
        <span className="eyebrow">Customer</span><h2>고객사 등록</h2>
        {canEdit && <form className="vertical-form" onSubmit={createCustomer}>
          <label>고객사 코드<input name="customer_code" required placeholder="CUST-001" /></label>
          <label>고객사명<input name="name" required placeholder="시연 고객사" /></label>
          <button className="primary">고객사 저장</button>
        </form>}
        <div className="simple-list">{customers.map((item) => <div key={item.id}><strong>{item.name}</strong><small>{item.customer_code} · 사이트 {item.site_count} · 자산 {item.asset_count}</small></div>)}</div>
      </article>
      <article className="panel">
        <span className="eyebrow">Site</span><h2>사이트 등록</h2>
        {canEdit && <form className="vertical-form" onSubmit={createSite}>
          <label>고객사<select name="customer_id" required><option value="">선택</option>{customers.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select></label>
          <label>사이트 코드<input name="site_code" required placeholder="SEOUL-DC" /></label>
          <label>사이트명<input name="name" required placeholder="서울 전산실" /></label>
          <button className="primary" disabled={!customers.length}>사이트 저장</button>
        </form>}
        {error && <p className="form-error">{error}</p>}
        <div className="simple-list">{sites.map((item) => <div key={item.id}><strong>{item.name}</strong><small>{item.customer_name} · 자산 {item.asset_count}</small></div>)}</div>
      </article>
    </section>
  )
}

function Checks({ checks }) {
  return (
    <section className="panel full-panel">
      <div className="panel-heading"><div><span className="eyebrow">Agentless collection</span><h2>인프라 점검 이력</h2></div><span className="subtle">최근 {checks.length}건</span></div>
      <div className="table-wrap"><table>
        <thead><tr><th>실행 시각</th><th>자산</th><th>상태</th><th>CPU</th><th>메모리</th><th>디스크</th><th>결과</th></tr></thead>
        <tbody>{checks.map((job) => <tr key={job.id}>
          <td>{job.started_at ? new Date(job.started_at).toLocaleString('ko-KR') : '-'}</td>
          <td><strong>{job.asset_name}</strong><small>{job.asset_tag}</small></td>
          <td><span className={`job job-${job.status.toLowerCase()}`}>{job.status}</span></td>
          <td>{job.cpu_percent === null ? '-' : `${job.cpu_percent}%`}</td><td>{job.memory_percent === null ? '-' : `${job.memory_percent}%`}</td><td>{job.max_disk_percent === null ? '-' : `${job.max_disk_percent}%`}</td>
          <td>{job.health_level || job.failure_stage || '-'}<small>{job.failure_message}</small></td>
        </tr>)}{checks.length === 0 && <tr><td colSpan="7" className="empty">점검 이력이 없습니다. 자산 화면에서 점검을 실행할 수 있습니다.</td></tr>}</tbody>
      </table></div>
    </section>
  )
}

function Software({ software, assets, onCreated, canEdit }) {
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  async function submit(event) {
    const form = event.currentTarget
    event.preventDefault()
    setError('')
    const data = Object.fromEntries(new FormData(form))
    for (const key of ['vendor', 'purl', 'support_end_date', 'lifecycle_source_url', 'asset_id']) if (!data[key]) data[key] = null
    if (data.asset_id) data.asset_id = Number(data.asset_id)
    try {
      await api('/software', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      form.reset()
      setOpen(false)
      onCreated('소프트웨어와 배포 관계를 등록했습니다.')
    } catch (reason) { setError(reason.message) }
  }
  return (
    <section className="panel full-panel">
      <div className="panel-heading">
        <div><span className="eyebrow">Infrastructure software</span><h2>인프라 소프트웨어</h2></div>
        {canEdit && <button className="primary" onClick={() => setOpen(!open)}>{open ? '닫기' : '+ 소프트웨어 등록'}</button>}
      </div>
      {open && (
        <form className="asset-form" onSubmit={submit}>
          <label>이름<input name="name" required placeholder="Ubuntu Server" /></label>
          <label>버전<input name="version" required placeholder="22.04 LTS" /></label>
          <label>공급사<input name="vendor" placeholder="Canonical" /></label>
          <label>분류<select name="product_type"><option value="OS">운영체제</option><option value="FIRMWARE">펌웨어</option><option value="HYPERVISOR">하이퍼바이저</option><option value="MIDDLEWARE">미들웨어</option><option value="DBMS">DBMS</option><option value="AGENT">관리 에이전트</option><option value="APPLICATION">애플리케이션</option></select></label>
          <label>purl<input name="purl" placeholder="pkg:generic/ubuntu@22.04" /></label>
          <label>지원종료일<input type="date" name="support_end_date" /></label>
          <label>근거 URL<input type="url" name="lifecycle_source_url" placeholder="https://..." /></label>
          <label>배포 자산<select name="asset_id"><option value="">나중에 연결</option>{assets.map((asset) => <option value={asset.id} key={asset.id}>{asset.asset_tag} · {asset.name}</option>)}</select></label>
          <label>환경<select name="environment"><option value="production">운영</option><option value="staging">스테이징</option><option value="development">개발</option></select></label>
          {error && <p className="form-error">{error}</p>}
          <button className="primary submit" type="submit">저장</button>
        </form>
      )}
      <div className="table-wrap">
        <table>
          <thead><tr><th>소프트웨어</th><th>공급사</th><th>식별자</th><th>배포 자산</th><th>지원 상태</th></tr></thead>
          <tbody>
            {software.map((item) => (
              <tr key={item.id}>
                <td><strong>{item.name}</strong><small>버전 {item.version}</small></td>
                <td>{item.vendor || '미입력'}</td>
                <td><code>{item.purl || item.cpe || '식별자 없음'}</code></td>
                <td>{item.asset_ids.length ? `${item.asset_ids.length}대 연결` : '연결 안 됨'}</td>
                <td><RiskBadge level={item.risk_level} /> <small>{item.days_left === null ? '날짜 미입력' : `${item.days_left}일`}</small></td>
              </tr>
            ))}
            {software.length === 0 && <tr><td colSpan="5" className="empty">등록된 소프트웨어가 없습니다.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function Sboms({ sboms, assets, onImported, canEdit, onViewCve, initialSbomId }) {
  const [exploring, setExploring] = useState(initialSbomId || null)
  const [file, setFile] = useState(null)
  const [assetId, setAssetId] = useState('')
  const [error, setError] = useState('')
  const [baseId, setBaseId] = useState('')
  const [targetId, setTargetId] = useState('')
  const [diff, setDiff] = useState(null)
  async function upload(event) {
    event.preventDefault()
    if (!file) return
    setError('')
    try {
      const document = JSON.parse(await file.text())
      const query = assetId ? `?asset_id=${assetId}` : ''
      await api(`/sboms/import${query}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(document) })
      setFile(null)
      onImported('SBOM을 분석해 저장했습니다.')
    } catch (reason) { setError(reason instanceof SyntaxError ? '올바른 JSON 파일이 아닙니다.' : reason.message) }
  }
  async function compare() {
    setError(''); setDiff(null)
    try { setDiff(await api(`/sboms/${baseId}/compare/${targetId}`)) }
    catch (reason) { setError(reason.message) }
  }
  return (
    <>
    <section className="split-grid sbom-grid">
      <article className="panel import-card">
        <span className="eyebrow">SOFTWARE INVENTORY · SPDX 2.3</span><h2>SBOM 가져오기</h2>
        <p>SBOM 생성 도구에서 내보낸 문서를 자산에 연결하고 구성요소·의존관계·품질을 검사합니다. 취약점 분석 결과는 CVE 조치 화면에서 함께 가져올 수 있습니다.</p>
        <form onSubmit={upload}>
          <label className="file-drop"><input type="file" accept="application/json,.json" onChange={(e) => setFile(e.target.files[0])} /><b>{file ? file.name : 'JSON 파일 선택'}</b><small>SPDX 2.3 우선 · CycloneDX 1.4~1.7 호환</small></label>
          <label>연결할 인프라 자산<select value={assetId} onChange={(e) => setAssetId(e.target.value)}><option value="">연결하지 않음</option>{assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.asset_tag} · {asset.name}</option>)}</select></label>
          {error && <p className="form-error">{error}</p>}
          <button className="primary wide" disabled={!canEdit || !file}>분석 후 가져오기</button>
        </form>
      </article>
      <article className="panel">
        <div className="panel-heading"><div><span className="eyebrow">Inventory</span><h2>가져온 SBOM</h2></div><span className="subtle">{sboms.length}건</span></div>
        <div className="sbom-list">
          {sboms.map((sbom) => (
            <div className="sbom-item" key={sbom.id}>
              <div><strong>{sbom.serial_number.replace('urn:uuid:', '').slice(0, 18)}</strong><small>{sbom.bom_format} {sbom.spec_version} · 문서 v{sbom.document_version}</small></div>
              <div className="score"><b>{sbom.quality_score}</b><small>품질 점수</small></div>
              <div className="counts"><span>{sbom.component_count} 구성요소</span><span>{sbom.dependency_count} 의존관계</span><button className="table-button" aria-label={`SBOM ${sbom.id} 상세 탐색`} onClick={() => setExploring(sbom.id)}>상세 탐색</button></div>
            </div>
          ))}
          {sboms.length === 0 && <p className="empty">가져온 SBOM이 없습니다.</p>}
        </div>
      </article>
    </section>
    {exploring && <SbomExplorer key={exploring} sbomId={exploring} request={api} download={download} canEdit={canEdit} onChanged={onImported} onClose={() => setExploring(null)} onViewCve={onViewCve} />}
    <section className="panel compare-panel">
      <div className="panel-heading"><div><span className="eyebrow">CHANGE ANALYSIS</span><h2>SBOM 버전 비교</h2></div></div>
      <div className="compare-controls">
        <label>기준 SBOM<select value={baseId} onChange={(event) => setBaseId(event.target.value)}><option value="">선택</option>{sboms.map((item) => <option value={item.id} key={item.id}>#{item.id} · {item.serial_number.slice(-12)}</option>)}</select></label>
        <label>대상 SBOM<select value={targetId} onChange={(event) => setTargetId(event.target.value)}><option value="">선택</option>{sboms.map((item) => <option value={item.id} key={item.id}>#{item.id} · {item.serial_number.slice(-12)}</option>)}</select></label>
        <button className="primary submit" disabled={!baseId || !targetId || baseId === targetId} onClick={compare}>비교</button>
      </div>
      {diff && <div className="diff-grid">
        <DiffList title="추가" items={diff.added} />
        <DiffList title="변경" items={diff.changed} />
        <DiffList title="삭제" items={diff.removed} />
        <article><b>동일</b><strong>{diff.unchanged_count}개</strong></article>
      </div>}
    </section>
    </>
  )
}

function DiffList({ title, items }) {
  return <article><b>{title}</b><strong>{items.length}개</strong>{items.slice(0, 5).map((item, index) => <small key={`${item.identity}:${item.before_version || ''}:${item.after_version || ''}:${index}`}>{item.name} {item.before_version || '-'} → {item.after_version || '-'}</small>)}</article>
}

function AnalysisJobs({ jobs, error, pendingAssets, onRetry, onCancel, onViewResult, canEdit }) {
  return <section className="panel full-panel">
    <div className="panel-heading"><div><span className="eyebrow">SERVER ANALYSIS</span><h2>서버 분석 작업</h2><small>작업 대상에서 취약점 분석을 요청하세요. 대기 → 수집 → 분석 → 저장 순서로 진행하며, 완료되면 결과를 확인할 수 있습니다.</small></div><span className="subtle">최근 {jobs.length}건 · 자동 갱신</span></div>
    {error && <p className="inline-result form-error" role="alert">{error}</p>}
    <div className="table-wrap"><table aria-label="서버 분석 작업"><thead><tr><th>요청 시각</th><th>대상 서버</th><th>진행 상태</th><th>결과·오류</th><th>확인</th></tr></thead><tbody>
      {jobs.map((job) => <tr key={job.id}>
        <td>{new Date(job.requested_at).toLocaleString('ko-KR')}<small>작업 #{job.id}{job.retry_of_id ? ` · 작업 #${job.retry_of_id} 재시도` : ''}</small></td>
        <td><strong>{job.asset_tag || `자산 #${job.asset_id}`}</strong><small>{job.asset_name}</small><small>{analysisScopeText[job.scan_scope] || scopeLabel(job.scan_scope)}</small></td>
        <td><span className={`job job-${job.status === 'SUCCESS' ? 'success' : job.status === 'FAILED' ? 'failed' : 'running'}`}>{analysisJobText[job.status] || job.status}</span>{job.finished_at && <small>{new Date(job.finished_at).toLocaleString('ko-KR')}</small>}</td>
        <td>{job.error_message ? <><strong>{job.error_message}</strong>{job.error_code && <small>{job.error_code}</small>}</> : job.status === 'SUCCESS' ? <><strong>분석 #{job.analysis_run_id}</strong><small>SBOM #{job.sbom_id}</small></> : <small>{job.status === 'CANCELLED' ? '분석을 취소했습니다.' : job.status === 'CANCEL_REQUESTED' ? '실행 중인 프로세스 종료를 확인하고 있습니다.' : '진행 상태를 자동으로 확인합니다.'}</small>}</td>
        <td>{job.status === 'SUCCESS' && job.sbom_id && <button className="table-button" aria-label={`작업 ${job.id} 결과 보기`} onClick={() => onViewResult(job.sbom_id)}>결과 보기</button>}{job.status === 'FAILED' && <button className="table-button" aria-label={`작업 ${job.id} 재시도`} disabled={!canEdit || pendingAssets.includes(job.asset_id) || jobs.some((item) => item.asset_id === job.asset_id && activeAnalysisJob(item))} onClick={() => onRetry(job)}>재시도</button>}{canEdit && activeAnalysisJob(job) && <button className="table-button" aria-label={`작업 ${job.id} 취소`} disabled={job.status === 'CANCEL_REQUESTED' || pendingAssets.includes(job.asset_id)} onClick={() => onCancel(job)}>분석 취소</button>}</td>
      </tr>)}
      {!jobs.length && <tr><td colSpan="5" className="empty">요청한 서버 분석이 없습니다. 작업 대상에서 서버의 취약점 분석을 시작하세요.</td></tr>}
    </tbody></table></div>
  </section>
}

function AnalysisComparison({ analyses, initialBaseId = '', initialTargetId = '' }) {
  const [baseId, setBaseId] = useState(String(initialBaseId))
  const [targetId, setTargetId] = useState(String(initialTargetId))
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [downloading, setDownloading] = useState('')
  const [page, setPage] = useState(0)
  const request = useRef(null)
  const reportRequest = useRef(null)
  const revision = useRef(0)
  const base = analyses.find((run) => String(run.id) === baseId)
  const candidates = base?.asset_id != null && base.scan_scope ? analyses.filter((run) => run.asset_id === base.asset_id && run.scan_scope === base.scan_scope && (Date.parse(run.imported_at) > Date.parse(base.imported_at) || (run.imported_at === base.imported_at && run.id > base.id))) : []
  const target = candidates.find((run) => String(run.id) === targetId)
  const pageSize = 100
  const findings = result?.findings || []
  const pageCount = Math.max(1, Math.ceil(findings.length / pageSize))
  const currentPage = Math.min(page, pageCount - 1)
  const label = (run) => `#${run.id} · ${run.asset_tag || `자산 #${run.asset_id}`} · ${analysisScopeText[run.scan_scope] || scopeLabel(run.scan_scope)}`

  useEffect(() => () => { request.current?.abort(); reportRequest.current?.abort() }, [])

  function resetResult() {
    revision.current += 1; request.current?.abort(); reportRequest.current?.abort()
    setResult(null); setError(''); setBusy(false); setDownloading(''); setPage(0)
  }
  async function compare() {
    if (!base || !target || busy) return
    const controller = new AbortController()
    request.current?.abort(); request.current = controller
    reportRequest.current?.abort(); setDownloading('')
    const requestedRevision = ++revision.current
    setBusy(true); setError(''); setResult(null); setPage(0)
    try {
      const data = await api(`/analyses/${base.id}/compare/${target.id}`, { signal: controller.signal })
      if (!controller.signal.aborted && requestedRevision === revision.current) setResult(data)
    } catch (reason) {
      if (!controller.signal.aborted && requestedRevision === revision.current) setError(`분석 비교 실패: ${reason.message}`)
    } finally {
      if (!controller.signal.aborted && requestedRevision === revision.current) setBusy(false)
    }
  }

  async function downloadReport(format) {
    if (!result || downloading || (reportRequest.current && !reportRequest.current.signal.aborted)) return
    const controller = new AbortController()
    reportRequest.current = controller
    const requestedRevision = revision.current
    setDownloading(format); setError('')
    try {
      await download(`/reports/analyses/${result.base.id}/compare/${result.target.id}.${format}`, `eolwatch-analysis-${result.base.id}-${result.target.id}.${format}`, controller.signal)
    } catch (reason) {
      if (!controller.signal.aborted && requestedRevision === revision.current) setError(`${format === 'pdf' ? '검증 보고서 PDF' : '검증 데이터 JSON'} 다운로드 실패: ${reason.message}`)
    } finally {
      if (reportRequest.current === controller) reportRequest.current = null
      if (!controller.signal.aborted && requestedRevision === revision.current) setDownloading('')
    }
  }

  return <section className="panel compare-panel">
    <div className="panel-heading"><div><span className="eyebrow">BEFORE · AFTER</span><h2>분석 전후 비교</h2><small>같은 서버와 같은 분석 범위의 이전 결과·이후 결과를 비교합니다. 미검출은 자동 조치 완료 판정이 아닙니다.</small></div></div>
    <div className="compare-controls">
      <label>이전 분석<select value={baseId} onChange={(event) => { resetResult(); setBaseId(event.target.value); setTargetId('') }}><option value="">이전 분석 선택</option>{analyses.filter((run) => run.asset_id != null && run.scan_scope).map((run) => <option key={run.id} value={run.id}>{label(run)}</option>)}</select></label>
      <label>이후 분석<select value={targetId} disabled={!base || !candidates.length} onChange={(event) => { resetResult(); setTargetId(event.target.value) }}><option value="">{base && !candidates.length ? '같은 서버·범위의 이후 분석이 없습니다' : '이후 분석 선택'}</option>{candidates.map((run) => <option key={run.id} value={run.id}>{label(run)}</option>)}</select></label>
      <button className="primary" disabled={!target || busy} onClick={compare}>{busy ? '비교 중…' : '분석 전후 비교'}</button>
    </div>
    {error && <p className="form-error compare-panel" role="alert">{error}</p>}
    {result && <>
      <p className="subtle compare-panel">분석 #{result.base.id} ({new Date(result.base.imported_at).toLocaleString('ko-KR')}) → 분석 #{result.target.id} ({new Date(result.target.imported_at).toLocaleString('ko-KR')}) · {result.target.asset_tag} · {analysisScopeText[result.target.scan_scope] || scopeLabel(result.target.scan_scope)}</p>
      <div className="panel-heading compare-panel"><small>분석 범위·도구·원본 식별정보·CVE 전후 결과를 포함합니다.</small><div className="action-row"><button className="table-button" aria-label="검증 보고서 PDF" disabled={Boolean(downloading)} onClick={() => downloadReport('pdf')}>{downloading === 'pdf' ? 'PDF 다운로드 중…' : '검증 보고서 PDF'}</button><button className="table-button" aria-label="검증 데이터 JSON" disabled={Boolean(downloading)} onClick={() => downloadReport('json')}>{downloading === 'json' ? 'JSON 다운로드 중…' : '검증 데이터 JSON'}</button></div></div>
      {!!result.warnings?.length && <ul className="inline-result" aria-label="분석 비교 주의사항">{result.warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul>}
      {!result.comparable && <p className="inline-result" role="status">분석 조건 차이를 함께 확인하세요. 아래는 원본 보고서의 탐지 변화입니다.</p>}
        <div className="diff-grid">{[['persistent', '계속 검출'], ['new', '새로 검출'], ['no_longer_detected', '재분석 미검출'], ['component_removed', '구성요소 제거']].map(([key, title]) => <article key={key}><b>{title}</b><strong>{result.summary[key]}건</strong></article>)}</div>
        <div className="table-wrap compare-panel"><table aria-label="분석 전후 CVE 비교"><thead><tr><th>CVE</th><th>구성요소</th><th>이전 버전</th><th>이후 버전</th><th>수정 버전</th><th>심각도</th><th>재분석 결과</th></tr></thead><tbody>
          {findings.slice(currentPage * pageSize, (currentPage + 1) * pageSize).map((finding, index) => <tr key={`${finding.cve_id}-${finding.component_name}-${index}`}><td><code>{finding.cve_id}</code></td><td><strong>{finding.component_name}</strong></td><td>{finding.before_versions?.join(', ') || '버전 정보 없음'}</td><td>{finding.after_versions?.join(', ') || '버전 정보 없음'}</td><td>{finding.fixed_versions?.join(', ') || '확인 필요'}</td><td><span className={`severity severity-${(finding.severity || 'UNKNOWN').toLowerCase()}`}>{finding.severity || 'UNKNOWN'}</span></td><td><span className={`job${finding.status === 'NEW' ? ' job-failed' : finding.status === 'PERSISTENT' ? ' job-running' : ''}`}>{comparisonStatusText[finding.status] || finding.status}</span></td></tr>)}
          {!findings.length && <tr><td colSpan="7" className="empty">비교할 CVE 탐지 결과가 없습니다.</td></tr>}
        </tbody></table></div>
        {!!findings.length && <div className="panel-heading compare-panel"><span className="subtle">비교 결과 총 {findings.length}건 · {currentPage * pageSize + 1}–{Math.min((currentPage + 1) * pageSize, findings.length)}건 표시</span><div className="action-row"><button className="table-button" aria-label="비교 이전 페이지" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>이전</button><span className="subtle">{currentPage + 1} / {pageCount} 페이지</span><button className="table-button" aria-label="비교 다음 페이지" disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)}>다음</button></div></div>}
    </>}
  </section>
}

function Security({ assets, analyses, sboms, users, onChanged, canEdit, sbomId, onSelectSbom, analysisJobs, jobsError, pendingAssets, onRetryAnalysis, onCancelAnalysis, onViewAnalysisResult, onViewSbom, onViewHistory }) {
  const [assetId, setAssetId] = useState('')
  const [file, setFile] = useState(null)
  const [importing, setImporting] = useState(false)
  const [importError, setImportError] = useState('')
  const [busy, setBusy] = useState(false)
  const [page, setPage] = useState({ sbomId, number: 0 })
  const [cveRevision, setCveRevision] = useState(0)
  const [cveRead, setCveRead] = useState(null)
  const [selectedFinding, setSelectedFinding] = useState(null)
  const scanRequest = useRef(null)
  const pageSize = 100
  const currentPage = page.sbomId === sbomId ? page.number : 0
  const cveKey = `${sbomId}:${currentPage}:${cveRevision}`
  const currentRead = cveRead?.key === cveKey ? cveRead : null
  const cveLoading = Boolean(sbomId && (!currentRead || currentRead.status === 'loading'))
  const cveError = currentRead?.error || ''
  const cveTotal = currentRead?.data?.total || 0
  const pageCount = Math.max(1, Math.ceil(cveTotal / pageSize))
  const visibleVulnerabilities = currentRead?.data?.items || []
  const refreshCves = () => setCveRevision((revision) => revision + 1)

  useEffect(() => {
    if (!sbomId) return
    const controller = new AbortController()
    setCveRead({ key: cveKey, status: 'loading' })
    const params = new URLSearchParams({ sbom_id: String(sbomId), status: 'ALL', limit: String(pageSize), offset: String(currentPage * pageSize) })
    api(`/vulnerability-work?${params}`, { signal: controller.signal }).then((result) => {
      if (controller.signal.aborted) return
      if (currentPage && currentPage * pageSize >= result.total) {
        setPage({ sbomId, number: Math.max(0, Math.ceil(result.total / pageSize) - 1) })
        return
      }
      setCveRead({ key: cveKey, status: 'success', data: result })
    }).catch((reason) => {
      if (!controller.signal.aborted) setCveRead({ key: cveKey, status: 'error', error: reason.message })
    })
    return () => controller.abort()
  }, [sbomId, currentPage, cveKey])

  useEffect(() => {
    setBusy(false)
    return () => { scanRequest.current?.abort(); scanRequest.current = null }
  }, [sbomId])

  function selectSbom(value) {
    onSelectSbom(value); setPage({ sbomId: value, number: 0 }); setSelectedFinding(null)
  }
  useEffect(() => { setSelectedFinding(null) }, [sbomId, currentPage])

  async function importAnalysis(event) {
    event.preventDefault()
    if (!canEdit || !assetId || !file || importing) return
    const form = event.currentTarget
    setImporting(true); setImportError('')
    try {
      const bundle = JSON.parse(await file.text())
      if (!bundle || typeof bundle !== 'object' || !bundle.sbom || !bundle.report) {
        throw new Error('SBOM과 취약점 보고서가 함께 담긴 분석 JSON 파일을 선택하세요.')
      }
      const result = await api('/analyses/import', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ asset_id: Number(assetId), sbom: bundle.sbom, report: bundle.report, scan_scope: bundle.scan_scope || 'uploaded SPDX SBOM' }),
      })
      selectSbom(String(result.sbom_id)); setFile(null); form.reset()
      await onChanged(`분석 결과 저장 완료: 구성요소 ${result.component_count}개 · CVE ${result.cve_count}개 · CVE 외 ${result.ignored_non_cve}건 제외`)
    } catch (reason) { setImportError(reason instanceof SyntaxError ? '올바른 JSON 파일이 아닙니다.' : reason.message) }
    finally { setImporting(false) }
  }

  async function scan() {
    if (!canEdit || !sbomId || scanRequest.current) return
    const controller = new AbortController()
    scanRequest.current = controller
    setBusy(true)
    try {
      const result = await api(`/vulnerabilities/scan/sbom/${sbomId}`, { method: 'POST', signal: controller.signal })
      if (controller.signal.aborted) return
      setSelectedFinding(null); refreshCves()
      await onChanged(`OSV 조회 완료: ${result.unique_vulnerabilities}건 · CVE 외 ${result.ignored_non_cve}건 · 버전 미확인 ${result.skipped_components || 0}건 · 철회 ${result.ignored_withdrawn || 0}건 · 영향 구간 외 ${result.ignored_unaffected || 0}건 제외`, false, controller.signal)
    } catch (reason) { if (!controller.signal.aborted) onChanged(reason.message, true, controller.signal) }
    finally { if (!controller.signal.aborted) { scanRequest.current = null; setBusy(false) } }
  }
  async function downloadBundle(run) {
    try { await download(`/analyses/${run.id}/bundle`, `eolwatch-analysis-${run.id}.json`) }
    catch (reason) { onChanged(reason.message, true) }
  }

  return <>
    <AnalysisJobs jobs={analysisJobs} error={jobsError} pendingAssets={pendingAssets} onRetry={onRetryAnalysis} onCancel={onCancelAnalysis} onViewResult={onViewAnalysisResult} canEdit={canEdit} />
    {canEdit && <section className="panel import-card compare-panel">
      <span className="eyebrow">SBOM · VULNERABILITY ANALYSIS</span><h2>분석 결과 가져오기</h2>
      <p>Syft로 생성한 SBOM과 Grype 취약점 보고서가 담긴 JSON 파일을 자산에 연결합니다. 분석 시점별 결과와 원본을 함께 보관합니다.</p>
      <form onSubmit={importAnalysis}>
        <label>분석 대상 자산<select required value={assetId} disabled={importing} onChange={(event) => setAssetId(event.target.value)}><option value="">자산 선택</option>{assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.asset_tag} · {asset.name}</option>)}</select></label>
        <label className="file-drop"><input aria-label="분석 결과 JSON 파일" type="file" accept="application/json,.json" disabled={importing} onChange={(event) => { setFile(event.target.files[0] || null); setImportError('') }} /><b>{file ? file.name : '분석 JSON 파일 선택'}</b><small>SBOM과 취약점 보고서가 담긴 파일</small></label>
        {importError && <p className="form-error" role="alert">{importError}</p>}
        <button className="primary wide" disabled={!assetId || !file || importing}>{importing ? '저장 중…' : '분석 결과 저장'}</button>
      </form>
    </section>}
    <section className="panel full-panel compare-panel">
      <div className="panel-heading"><div><span className="eyebrow">ANALYSIS HISTORY</span><h2>분석 이력</h2></div><span className="subtle">최근 {analyses.length}건</span><button className="secondary" onClick={onViewHistory}>전체 프로젝트·이력 검색</button></div>
      <div className="table-wrap"><table aria-label="분석 이력"><thead><tr><th>등록 시각</th><th>대상·범위</th><th>분석 도구</th><th>결과</th><th>확인</th></tr></thead>
        <tbody>{analyses.map((run) => <tr key={run.id}>
          <td>{new Date(run.imported_at).toLocaleString('ko-KR')}<small>분석 #{run.id} · SBOM #{run.sbom_id}</small></td>
          <td><strong>{run.asset_tag} · {run.asset_name}</strong><small>{analysisScopeText[run.scan_scope] || scopeLabel(run.scan_scope)}</small></td>
          <td><strong>{run.scanner} {run.scanner_version}</strong><small>SBOM 생성: {run.generator || '미상'}</small>{(run.database_info?.built || run.database_info?.status?.built) && <small>DB 기준: {new Date(run.database_info.built || run.database_info.status.built).toLocaleString('ko-KR')}</small>}</td>
          <td><strong>CVE {run.cve_count}개 · 구성요소 연결 {run.link_count}건</strong><small>구성요소 {run.component_count}개 · 전체 탐지 {run.match_count}건 · CVE 외 {run.ignored_non_cve}건</small></td>
          <td><div className="action-row"><button className="table-button" aria-label={`분석 ${run.id} CVE 보기`} onClick={() => selectSbom(String(run.sbom_id))}>CVE 보기</button><button className="table-button" aria-label={`분석 ${run.id} 원본 다운로드`} onClick={() => downloadBundle(run)}>원본 JSON</button></div></td>
        </tr>)}{!analyses.length && <tr><td colSpan="5" className="empty">가져온 분석 결과가 없습니다.</td></tr>}</tbody>
      </table></div>
    </section>
    <AnalysisComparison analyses={analyses} />
    <section className="panel full-panel compare-panel">
    <div className="panel-heading">
      <div><span className="eyebrow">CVE · VEX</span><h2>CVE 조치 현황</h2><small>선택한 SBOM의 Grype 분석 및 OSV 조회 결과 중 CVE 식별자가 있는 항목을 표시합니다. 조치 상태는 담당자가 근거를 확인한 뒤 수동으로 기록합니다.</small></div>
      <div className="action-row"><label>확인할 SBOM<select value={sbomId} onChange={(event) => selectSbom(event.target.value)}><option value="">SBOM 선택</option>{sboms.map((item) => <option value={item.id} key={item.id}>#{item.id} · {analyses.find((run) => run.sbom_id === item.id)?.asset_tag || 'SBOM'} · 구성요소 {item.component_count}</option>)}</select></label>{canEdit && <button className="primary" disabled={!sbomId || busy} onClick={scan}>{busy ? '조회 중…' : 'OSV 조회'}</button>}</div>
    </div>
    {sbomId && <button className="secondary" onClick={() => onViewSbom(Number(sbomId))}>선택한 SBOM의 구성요소·지원 일정 보기</button>}
    {selectedFinding && <VulnerabilityActions key={selectedFinding.link_id} finding={selectedFinding} analyses={analyses} users={users} canEdit={canEdit} request={api} onSaved={() => { setSelectedFinding(null); refreshCves(); return onChanged('조치 내용과 이력을 저장했습니다.') }} onClose={() => setSelectedFinding(null)} />}
    {cveLoading && <p role="status">CVE 결과를 불러오는 중…</p>}
    {cveError && <div role="alert"><p className="form-error">CVE 결과 조회 실패: {cveError}</p><button className="secondary" type="button" onClick={refreshCves}>CVE 조회 다시 시도</button></div>}
    <div className="table-wrap"><table aria-label="선택한 SBOM의 CVE"><thead><tr><th>CVE·출처</th><th>영향 자산</th><th>구성요소</th><th>수정 버전</th><th>심각도</th><th>조치 상태</th></tr></thead>
      <tbody>{visibleVulnerabilities.map((item) => <tr key={item.link_id}><td><code>{item.cve_id}</code><small>{item.finding_source || item.source || '출처 미상'}{item.analysis_run_id ? ` · 분석 #${item.analysis_run_id}` : ''}</small><small>{item.summary || '설명 없음'}</small></td><td><strong>{item.asset_tag || '미연결'}</strong><small>{item.asset_name || 'SBOM에 자산을 연결하세요'}</small></td><td><strong>{item.component_name}</strong><small>분석 당시 {item.component_version || '버전 미상'}</small></td><td><strong>{item.fixed_versions?.length ? item.fixed_versions.join(', ') : item.fixed_version || '확인 필요'}</strong></td><td><span className={`severity severity-${item.severity.toLowerCase()}`}>{item.severity}</span></td><td><span aria-label={`${item.cve_id} ${item.component_name} 조치 상태`}>{vexStatusText[item.vex_status] || item.vex_status}</span><small>담당 {item.assignee_username || '미지정'}</small>{item.due_date && <small>기한 {item.due_date}</small>}<button className="table-button" aria-label={`${item.cve_id} ${item.component_name} ${canEdit ? '조치 관리' : '조치 이력'}`} onClick={() => setSelectedFinding(item)}>{canEdit ? '조치 관리' : '조치 이력'}</button></td></tr>)}{!cveLoading && !cveError && !visibleVulnerabilities.length && <tr><td colSpan="6" className="empty">{sbomId ? '이 SBOM에 저장된 CVE 결과가 없습니다.' : '분석 이력에서 CVE 보기를 누르거나 SBOM을 선택하세요.'}</td></tr>}</tbody>
    </table></div>
    {!cveLoading && !cveError && cveTotal > 0 && <div className="panel-heading">
      <span className="subtle">총 {cveTotal}건 · {currentPage * pageSize + 1}–{Math.min(currentPage * pageSize + visibleVulnerabilities.length, cveTotal)}건 표시</span>
      <div className="action-row"><button className="table-button" disabled={currentPage === 0} onClick={() => setPage({ sbomId, number: currentPage - 1 })}>이전 페이지</button><span className="subtle">{currentPage + 1} / {pageCount} 페이지</span><button className="table-button" disabled={currentPage + 1 >= pageCount} onClick={() => setPage({ sbomId, number: currentPage + 1 })}>다음 페이지</button></div>
    </div>}
  </section>
  </>
}

function Operations({ notifications, auditLogs, users, onChanged, canEdit }) {
  async function createUser(event) {
    const form = event.currentTarget
    event.preventDefault()
    try {
      const data = Object.fromEntries(new FormData(form))
      await api('/auth/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      form.reset(); onChanged('사용자 계정을 만들었습니다.')
    } catch (reason) { onChanged(reason.message, true) }
  }
  async function sendSummary() {
    try {
      const result = await api('/notifications/risk-summary', { method: 'POST' })
      onChanged(result.status === 'SUCCESS' ? 'Teams에 위험 건수 요약을 보냈습니다.' : result.error_message)
    } catch (reason) { onChanged(reason.message, true) }
  }
  async function getReport(path, filename) {
    try { await download(path, filename); onChanged('PDF 보고서를 내려받았습니다.') }
    catch (reason) { onChanged(reason.message, true) }
  }
  return <>
    <section className="metric-grid operations-grid">
      <article className="panel operation-card"><span className="eyebrow">REPORT</span><h2>PDF 보고서</h2><p>현재 위험 현황과 최근 점검 이력을 제출용 PDF로 생성합니다.</p><div className="action-row"><button className="primary" onClick={() => getReport('/reports/lifecycle.pdf', 'eolwatch-lifecycle.pdf')}>지원종료 보고서</button><button className="secondary" onClick={() => getReport('/reports/daily-checks.pdf', 'eolwatch-checks.pdf')}>점검 보고서</button></div></article>
      <article className="panel operation-card"><span className="eyebrow">TEAMS WORKFLOWS</span><h2>운영 알림</h2><p>내부 식별정보를 제외한 위험 등급별 건수만 전송합니다.</p><button className="primary" disabled={!canEdit} onClick={sendSummary}>위험 요약 전송</button></article>
    </section>
    {canEdit && <section className="split-grid operations-section">
      <article className="panel"><span className="eyebrow">ACCESS CONTROL</span><h2>사용자 관리</h2><form className="vertical-form" onSubmit={createUser}><label>아이디<input name="username" minLength="3" required /></label><label>초기 비밀번호<input name="password" type="password" minLength="10" required /></label><label>권한<select name="role"><option value="VIEWER">조회자</option><option value="ADMIN">관리자</option></select></label><button className="primary">계정 생성</button></form><div className="simple-list">{users.map((item) => <div key={item.id}><strong>{item.username}</strong><small>{item.role} · {item.active ? '사용 중' : '비활성'}</small></div>)}</div></article>
      <article className="panel"><span className="eyebrow">DELIVERY HISTORY</span><h2>알림 전송 이력</h2><div className="simple-list">{notifications.map((item) => <div key={item.id}><strong>{item.event_type} · {item.status}</strong><small>{new Date(item.created_at).toLocaleString('ko-KR')} · {item.error_message || item.recipient_label}</small></div>)}{!notifications.length && <p className="empty">전송 이력이 없습니다.</p>}</div></article>
    </section>}
    {canEdit && <section className="panel full-panel audit-panel"><div className="panel-heading"><div><span className="eyebrow">AUDIT</span><h2>변경 감사 로그</h2></div><span className="subtle">최근 {auditLogs.length}건</span></div><div className="table-wrap"><table><thead><tr><th>시각</th><th>사용자</th><th>방식</th><th>경로</th><th>결과</th></tr></thead><tbody>{auditLogs.map((item) => <tr key={item.id}><td>{new Date(item.created_at).toLocaleString('ko-KR')}</td><td>{item.username}</td><td><code>{item.method}</code></td><td>{item.path}</td><td>{item.status_code}</td></tr>)}</tbody></table></div></section>}
  </>
}

export default function App() {
  const sharedAssetId = Number(new URLSearchParams(window.location.search).get('asset')) || null
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('eolwatch_user')) }
    catch { return null }
  })
  const [tab, setTab] = useState(sharedAssetId ? 'assets' : 'overview')
  const [summary, setSummary] = useState(EMPTY_SUMMARY)
  const [assets, setAssets] = useState([])
  const [software, setSoftware] = useState([])
  const [sboms, setSboms] = useState([])
  const [customers, setCustomers] = useState([])
  const [sites, setSites] = useState([])
  const [checks, setChecks] = useState([])
  const [analyses, setAnalyses] = useState([])
  const [analysisJobs, setAnalysisJobs] = useState([])
  const [jobsError, setJobsError] = useState('')
  const [pendingAssets, setPendingAssets] = useState([])
  const [selectedSbomId, setSelectedSbomId] = useState('')
  const requestedJobs = useRef(new Set())
  const requestingAssets = useRef(new Set())
  const jobRequests = useRef(new Set())
  const comparisonRequest = useRef(null)
  const jobsRevision = useRef(0)
  const messageTimer = useRef(null)
  const [notifications, setNotifications] = useState([])
  const [auditLogs, setAuditLogs] = useState([])
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [focusedAssetId, setFocusedAssetId] = useState(sharedAssetId)
  const [projectContext, setProjectContext] = useState({})
  const [analysisInput, setAnalysisInput] = useState({})
  const [explorerSbomId, setExplorerSbomId] = useState(null)
  const [comparison, setComparison] = useState(null)
  const [workQuery, setWorkQuery] = useState(null)

  const canEdit = user?.role === 'ADMIN'
  const logout = useCallback(() => {
    localStorage.removeItem('eolwatch_token'); localStorage.removeItem('eolwatch_user'); setUser(null)
  }, [])
  const load = useCallback(async (message = '', isError = false, signal) => {
    try {
      const [nextSummary, nextAssets, nextSoftware, nextSboms, nextCustomers, nextSites, nextChecks, nextAnalyses, nextNotifications, nextAuditLogs, nextUsers] = await Promise.all([
        ...['/dashboard/summary', '/assets', '/software', '/sboms', '/customers', '/sites', '/checks', '/analyses', '/notifications'].map((path) => api(path, { signal })),
        canEdit ? api('/auth/audit-logs', { signal }) : Promise.resolve([]), canEdit ? api('/auth/users', { signal }) : Promise.resolve([]),
      ])
      if (signal?.aborted) return false
      setSummary(nextSummary); setAssets(nextAssets); setSoftware(nextSoftware); setSboms(nextSboms); setCustomers(nextCustomers); setSites(nextSites); setChecks(nextChecks); setAnalyses(nextAnalyses); setNotifications(nextNotifications); setAuditLogs(nextAuditLogs); setUsers(nextUsers)
      setError(isError ? message : ''); setMessage(isError ? '' : message)
      clearTimeout(messageTimer.current)
      if (message) messageTimer.current = setTimeout(() => setMessage(''), 2500)
      return true
    } catch (reason) {
      if (signal?.aborted) return false
      if (reason.message.includes('로그인') || reason.message.includes('토큰')) logout()
      else setError(`API 연결 실패: ${reason.message}`)
      return false
    }
    finally { if (!signal?.aborted) setLoading(false) }
  }, [canEdit, logout])

  function acceptedAnalysisJob(job) {
    jobsRevision.current += 1
    requestedJobs.current.add(job.id)
    setAnalysisJobs((current) => [job, ...current.filter((item) => item.id !== job.id)])
    setTab('security')
    setMessage('분석 요청을 저장했습니다. 작업 진행 상태를 확인하세요.')
  }

  function viewProjects(assetId = null) {
    setProjectContext({ assetId }); setTab('projects')
  }

  function viewSbom(sbomId) {
    setExplorerSbomId(sbomId); setTab('sbom')
  }

  function viewAssetWork(assetId) {
    setWorkQuery({ filters: { q: '', asset_id: String(assetId), status: 'OPEN', severity: '', assignee_id: '', unassigned: false, overdue: false }, offset: 0, limit: 25, revision: 0 })
    setTab('work')
  }

  async function viewComparison(baseId, targetId, signal) {
    if (comparisonRequest.current || signal?.aborted) return
    const controller = new AbortController(); jobRequests.current.add(controller)
    comparisonRequest.current = controller
    const abort = () => controller.abort()
    signal?.addEventListener('abort', abort, { once: true })
    try {
      const runs = await Promise.all([baseId, targetId].map((id) => api(`/analyses/runs/${id}`, { signal: controller.signal })))
      if (!controller.signal.aborted) { setComparison({ runs, baseId, targetId }); setTab('comparison') }
    } catch (reason) { if (!controller.signal.aborted) setError(reason.message) }
    finally { jobRequests.current.delete(controller); signal?.removeEventListener('abort', abort); if (comparisonRequest.current === controller) comparisonRequest.current = null }
  }

  useEffect(() => () => { comparisonRequest.current?.abort(); comparisonRequest.current = null }, [tab, projectContext.assetId, projectContext.scanScope, user?.id])

  async function cancelAnalysis(job) {
    if (!canEdit || requestingAssets.current.has(job.asset_id)) return
    const controller = new AbortController(); jobRequests.current.add(controller)
    requestingAssets.current.add(job.asset_id); setPendingAssets([...requestingAssets.current]); jobsRevision.current += 1
    try {
      const updated = await api(`/analyses/jobs/${job.id}/cancel`, { method: 'POST', signal: controller.signal })
      if (!controller.signal.aborted) {
        jobsRevision.current += 1
        setAnalysisJobs((current) => current.map((item) => item.id === updated.id ? updated : item))
        setMessage(updated.status === 'CANCELLED' ? '대기 중인 분석을 취소했습니다.' : '취소를 요청했습니다. 프로세스 종료를 확인할 때까지 기다려 주세요.')
      }
    } catch (reason) { if (!controller.signal.aborted) setError(reason.message) }
    finally {
      jobRequests.current.delete(controller); requestingAssets.current.delete(job.asset_id)
      if (!controller.signal.aborted) setPendingAssets([...requestingAssets.current])
    }
  }

  async function requestAnalysis(assetId, retryJobId, scanScope = 'ubuntu-dpkg-installed') {
    if (!canEdit || requestingAssets.current.has(assetId)) return
    const current = analysisJobs.find((job) => job.asset_id === assetId && activeAnalysisJob(job))
    if (current) { requestedJobs.current.add(current.id); setTab('security'); return }
    const controller = new AbortController()
    jobRequests.current.add(controller)
    requestingAssets.current.add(assetId); setPendingAssets([...requestingAssets.current])
    jobsRevision.current += 1
    setError('')
    try {
      const options = { method: 'POST', signal: controller.signal }
      if (!retryJobId) { options.headers = { 'Content-Type': 'application/json' }; options.body = JSON.stringify({ scan_scope: scanScope }) }
      const job = await api(retryJobId ? `/analyses/jobs/${retryJobId}/retry` : `/analyses/assets/${assetId}/jobs`, options)
      if (controller.signal.aborted) return
      jobsRevision.current += 1
      requestedJobs.current.add(job.id)
      setAnalysisJobs((previous) => [job, ...previous.filter((item) => item.id !== job.id)])
      setJobsError(''); setTab('security')
    } catch (reason) {
      if (!controller.signal.aborted) setError(`분석 요청 실패: ${reason.message}`)
    } finally {
      jobRequests.current.delete(controller)
      if (!controller.signal.aborted) {
        requestingAssets.current.delete(assetId); setPendingAssets([...requestingAssets.current])
      }
    }
  }

  async function viewAnalysisResult(sbomId) {
    const controller = new AbortController()
    jobRequests.current.add(controller)
    try {
      if (!sboms.some((sbom) => sbom.id === sbomId) && !await load('', false, controller.signal)) return
      if (!controller.signal.aborted) { setSelectedSbomId(String(sbomId)); setTab('security') }
    } finally { jobRequests.current.delete(controller) }
  }

  useEffect(() => {
    if (!user) return
    const controller = new AbortController()
    setLoading(true); load('', false, controller.signal)
    return () => { controller.abort(); clearTimeout(messageTimer.current) }
  }, [user?.id, user?.role, load])

  useEffect(() => {
    function navigate(event) {
      const detail = event.detail || {}
      if (detail.target === 'cve') viewAssetWork(detail.value)
      if (detail.target === 'sbom') viewSbom(detail.value)
      if (detail.target === 'management') { setFocusedAssetId(detail.value); setTab('management') }
    }
    window.addEventListener('eolwatch-navigate', navigate)
    return () => window.removeEventListener('eolwatch-navigate', navigate)
  }, [])

  useEffect(() => {
    if (!user) return
    const controller = new AbortController()
    let timer
    let observedSuccesses
    const tracking = new Set()
    setAnalysisJobs([]); setJobsError(''); setPendingAssets([]); setSelectedSbomId('')
    async function pollJobs() {
      const revision = jobsRevision.current
      try {
        const [recent, active] = await Promise.all(['/analyses/jobs', '/analyses/jobs/active'].map((path) => api(path, { signal: controller.signal })))
        const merged = new Map([...recent, ...active].map((job) => [job.id, job]))
        for (const job of active) tracking.add(job.id)
        for (const id of requestedJobs.current) tracking.add(id)
        const missing = [...tracking].filter((id) => !merged.has(id))
        const tracked = await Promise.all(missing.map((id) => api(`/analyses/jobs/${id}`, { signal: controller.signal }).catch((reason) => {
          if (reason.status === 404) { tracking.delete(id); requestedJobs.current.delete(id); return null }
          throw reason
        })))
        for (const job of tracked) if (job) merged.set(job.id, job)
        const jobs = [...merged.values()].sort((left, right) => right.id - left.id)
        for (const job of jobs) if (!activeAnalysisJob(job)) tracking.delete(job.id)
        if (controller.signal.aborted || revision !== jobsRevision.current) return
        setAnalysisJobs(jobs); setJobsError('')
        if (!observedSuccesses) observedSuccesses = new Set(jobs.filter((job) => job.status === 'SUCCESS').map((job) => job.id))
        const newSuccesses = jobs.filter((job) => job.status === 'SUCCESS' && !observedSuccesses.has(job.id))
        const completed = jobs.filter((job) => requestedJobs.current.has(job.id) && job.status === 'SUCCESS' && job.sbom_id)
        jobs.filter((job) => ['FAILED', 'CANCELLED'].includes(job.status)).forEach((job) => requestedJobs.current.delete(job.id))
        if (completed.length) {
          const loaded = await load('서버 분석이 완료되었습니다. 새 SBOM의 CVE 결과를 확인하세요.', false, controller.signal)
          if (loaded && !controller.signal.aborted) {
            completed.forEach((job) => requestedJobs.current.delete(job.id))
            newSuccesses.forEach((job) => observedSuccesses.add(job.id))
            setSelectedSbomId(String(completed[0].sbom_id)); setTab('security')
          }
        } else if (newSuccesses.length) {
          const nextSummary = await api('/dashboard/summary', { signal: controller.signal })
          if (!controller.signal.aborted) {
            setSummary(nextSummary); newSuccesses.forEach((job) => observedSuccesses.add(job.id))
          }
        }
      } catch (reason) {
        if (!controller.signal.aborted) setJobsError(`분석 상태를 갱신하지 못했습니다: ${reason.message} 잠시 후 다시 확인합니다.`)
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(pollJobs, 3000)
      }
    }
    pollJobs()
    return () => {
      controller.abort(); clearTimeout(timer)
      jobRequests.current.forEach((request) => request.abort()); jobRequests.current.clear()
      requestingAssets.current.clear(); requestedJobs.current.clear()
    }
  }, [user?.id, user?.role, load])

  if (!user) return <Login onLogin={setUser} />

  return (
    <div className="app-shell">
      <aside>
        <div className="brand"><span className="brand-mark">E</span><div><strong>EOLWatch</strong><small>Lifecycle Intelligence</small></div></div>
        <nav>
          <button className={tab === 'overview' ? 'active' : ''} onClick={() => setTab('overview')}><span>⌁</span> 운영 개요</button>
          <button className={tab === 'organization' ? 'active' : ''} onClick={() => setTab('organization')}><span>△</span> 고객·사이트</button>
          <button className={tab === 'assets' ? 'active' : ''} onClick={() => setTab('assets')}><span>□</span> 작업 대상</button>
          <button className={tab === 'projects' ? 'active' : ''} onClick={() => setTab('projects')}><span>▤</span> 프로젝트·분석 이력</button>
          <button className={tab === 'lifecycle' ? 'active' : ''} onClick={() => setTab('lifecycle')}><span>◷</span> EOL 일정 조회</button>
          <button className={tab === 'analysis' ? 'active' : ''} onClick={() => setTab('analysis')}><span>▷</span> 프로젝트 분석</button>
          <button className={tab === 'management' ? 'active' : ''} onClick={() => setTab('management')}><span>▦</span> 제품·계약</button>
          <button className={tab === 'software' ? 'active' : ''} onClick={() => setTab('software')}><span>○</span> 소프트웨어 원장</button>
          <button className={tab === 'sbom' ? 'active' : ''} onClick={() => setTab('sbom')}><span>◇</span> SBOM 원장</button>
          <button className={tab === 'security' ? 'active' : ''} onClick={() => setTab('security')}><span>!</span> CVE 조치</button>
          <button className={tab === 'work' ? 'active' : ''} onClick={() => setTab('work')}><span>☷</span> 조치 작업목록</button>
          <button className={tab === 'checks' ? 'active' : ''} onClick={() => setTab('checks')}><span>✓</span> 수집 실행 이력</button>
          <button className={tab === 'operations' ? 'active' : ''} onClick={() => setTab('operations')}><span>≡</span> 운영·보고서</button>
        </nav>
        <div className="standard-note"><b>{user.username}</b><p>{canEdit ? '관리자' : '조회자'} 권한으로 접속했습니다.</p><button className="logout" onClick={logout}>로그아웃</button></div>
      </aside>
      <main>
        <header><div><span className="eyebrow">INFRASTRUCTURE OPERATIONS</span><h1>{{ overview: '운영 개요', organization: '고객사와 사이트', assets: '작업 대상 자산', analysis: '프로젝트 분석과 예약', projects: '프로젝트와 전체 분석 이력', comparison: '선택한 분석 전후 비교', lifecycle: '공개 EOL 일정과 적용 근거', management: '제품 수명주기와 계약', software: '소프트웨어 원장', sbom: 'SBOM 원장', security: 'CVE 조치 현황', work: '조치 작업목록', checks: '수집 실행 이력', operations: '운영과 보고서' }[tab]}</h1></div><div className="today"><small>기준일</small><strong>{new Intl.DateTimeFormat('ko-KR', { dateStyle: 'long' }).format(new Date())}</strong></div></header>
        {error && <div className="alert error">{error}</div>}
        {message && <div className="alert success">{message}</div>}
        {loading ? <div className="loading">데이터를 불러오는 중입니다…</div> : tab === 'overview' ? <Overview summary={summary} onViewResult={viewAnalysisResult} analysisJobs={analysisJobs} /> : tab === 'organization' ? <Organization customers={customers} sites={sites} onChanged={load} canEdit={canEdit} /> : tab === 'assets' ? <Assets assets={assets} sites={sites} onChanged={load} canEdit={canEdit} analysisJobs={analysisJobs} pendingAssets={pendingAssets} onStartAnalysis={requestAnalysis} focusedAssetId={focusedAssetId} onViewProjects={viewProjects} /> : tab === 'projects' ? <ProjectHub assets={assets} canEdit={canEdit} request={api} download={download} onChanged={load} onJobQueued={acceptedAnalysisJob} onViewResult={viewAnalysisResult} onViewSbom={viewSbom} onCompare={viewComparison} onNewAnalysis={(input) => { setAnalysisInput(input); setTab('analysis') }} initialAssetId={projectContext.assetId} initialScope={projectContext.scanScope} onSelectionChange={setProjectContext} onViewWork={viewAssetWork} /> : tab === 'comparison' && comparison ? <><button className="secondary" onClick={() => setTab('projects')}>프로젝트 이력으로 돌아가기</button><AnalysisComparison key={`${comparison.baseId}-${comparison.targetId}`} analyses={comparison.runs} initialBaseId={comparison.baseId} initialTargetId={comparison.targetId} /></> : tab === 'lifecycle' ? <LifecycleCatalog api={api} isAdmin={canEdit} onError={(text) => setError(text)} onRefresh={load} /> : tab === 'analysis' ? <AnalysisTargets assets={assets} canEdit={canEdit} request={api} onJobQueued={acceptedAnalysisJob} initialAssetId={analysisInput.assetId} initialProjectName={analysisInput.projectName} initialScope={analysisInput.scanScope} initialTargetPath={analysisInput.targetPath} /> : tab === 'management' ? <ManagementWorkspace assets={assets} customers={customers} sites={sites} canEdit={canEdit} request={api} onChanged={load} onViewAsset={(id) => { setFocusedAssetId(id); setTab('assets') }} /> : tab === 'software' ? <Software software={software} assets={assets} onCreated={load} canEdit={canEdit} /> : tab === 'checks' ? <Checks checks={checks} /> : tab === 'security' ? <Security assets={assets} analyses={analyses} sboms={sboms} users={users} onChanged={load} canEdit={canEdit} sbomId={selectedSbomId} onSelectSbom={setSelectedSbomId} analysisJobs={analysisJobs} jobsError={jobsError} pendingAssets={pendingAssets} onRetryAnalysis={(job) => requestAnalysis(job.asset_id, job.id)} onViewAnalysisResult={viewAnalysisResult} onCancelAnalysis={cancelAnalysis} onViewSbom={viewSbom} onViewHistory={() => viewProjects()} /> : tab === 'work' ? <VulnerabilityWorklist assets={assets} users={users} analyses={analyses} canEdit={canEdit} request={api} onChanged={load} onViewResult={viewAnalysisResult} initialQuery={workQuery} onQueryChange={setWorkQuery} /> : tab === 'operations' ? <Operations notifications={notifications} auditLogs={auditLogs} users={users} onChanged={load} canEdit={canEdit} /> : <Sboms sboms={sboms} assets={assets} onImported={load} canEdit={canEdit} onViewCve={viewAnalysisResult} initialSbomId={explorerSbomId} />}
      </main>
    </div>
  )
}
