import { useEffect, useState } from 'react'

const EMPTY_SUMMARY = {
  assets: 0,
  software_products: 0,
  sbom_documents: 0,
  components: 0,
  dependencies: 0,
  lifecycle_risk: { EXPIRED: 0, CRITICAL: 0, WARN: 0, SAFE: 0, UNKNOWN: 0 },
  sbom_quality: { average_score: 0, below_70: 0 },
  urgent_items: [],
}

const riskText = { EXPIRED: '지원 종료', CRITICAL: '긴급', WARN: '주의', SAFE: '안전', UNKNOWN: '미확인' }
const typeText = { server: '서버', storage: '스토리지', network: '네트워크', security: '보안장비', vm: '가상머신', cloud: '클라우드', other: '기타' }

async function api(path, options) {
  const headers = new Headers(options?.headers || {})
  const token = localStorage.getItem('eolwatch_token')
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const response = await fetch(`/api${path}`, { ...options, headers })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(typeof body.detail === 'string' ? body.detail : '요청을 처리하지 못했습니다.')
  }
  if (response.status === 204) return null
  return response.json()
}

async function download(path, filename) {
  const token = localStorage.getItem('eolwatch_token')
  const response = await fetch(`/api${path}`, { headers: { Authorization: `Bearer ${token}` } })
  if (!response.ok) throw new Error('보고서를 내려받지 못했습니다.')
  const url = URL.createObjectURL(await response.blob())
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
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

function Overview({ summary }) {
  const risks = ['EXPIRED', 'CRITICAL', 'WARN', 'SAFE', 'UNKNOWN']
  const maxRisk = Math.max(...risks.map((risk) => summary.lifecycle_risk[risk] || 0), 1)
  return (
    <>
      <section className="metric-grid">
        <Metric label="인프라 자산" value={summary.assets} detail="물리 · 가상 · 클라우드" />
        <Metric label="인프라 SW" value={summary.software_products} detail="OS · 펌웨어 · 미들웨어" />
        <Metric label="SBOM" value={summary.sbom_documents} detail={`${summary.components}개 구성요소`} />
        <Metric label="SBOM 품질" value={`${summary.sbom_quality.average_score}%`} detail={`70점 미만 ${summary.sbom_quality.below_70}건`} />
      </section>

      <section className="split-grid">
        <article className="panel">
          <div className="panel-heading">
            <div><span className="eyebrow">통합 수명주기</span><h2>지원종료 위험 분포</h2></div>
            <span className="subtle">자산 + 소프트웨어</span>
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

function Assets({ assets, sites, onChanged, canEdit }) {
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  const [csvResult, setCsvResult] = useState(null)
  async function submit(event) {
    event.preventDefault()
    setError('')
    const data = Object.fromEntries(new FormData(event.currentTarget))
    for (const key of ['site_id', 'manufacturer', 'model', 'site', 'ip_address', 'ssh_username', 'support_end_date', 'lifecycle_source_url']) if (!data[key]) data[key] = null
    if (data.site_id) data.site_id = Number(data.site_id)
    data.monitored = Boolean(data.monitored)
    try {
      await api('/assets', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      event.currentTarget.reset()
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
      <div className="panel-heading">
        <div><span className="eyebrow">Infrastructure</span><h2>인프라 자산</h2></div>
        <div className="action-row">
          {canEdit && <label className="file-button">CSV 등록<input type="file" accept=".csv,text/csv" onChange={importCsv} /></label>}
          {canEdit && <button className="primary" onClick={() => setOpen(!open)}>{open ? '닫기' : '+ 자산 등록'}</button>}
        </div>
      </div>
      {csvResult && <div className="inline-result">전체 {csvResult.total_rows}행 · 성공 {csvResult.created} · 실패 {csvResult.failed}{csvResult.errors.map((item) => <small key={item.row}>{item.row}행 {item.asset_tag || '-'}: {item.message}</small>)}</div>}
      {open && (
        <form className="asset-form" onSubmit={submit}>
          <label>자산번호<input name="asset_tag" required placeholder="SRV-001" /></label>
          <label>자산명<input name="name" required placeholder="운영 웹 서버" /></label>
          <label>유형<select name="asset_type" defaultValue="server">{Object.entries(typeText).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label>
          <label>제조사<input name="manufacturer" placeholder="Dell" /></label>
          <label>모델<input name="model" placeholder="PowerEdge R740" /></label>
          <label>고객 사이트<select name="site_id"><option value="">연결하지 않음</option>{sites.map((site) => <option value={site.id} key={site.id}>{site.customer_name} · {site.name}</option>)}</select></label>
          <label>랙·위치 메모<input name="site" placeholder="A랙 10U" /></label>
          <label>관리 IP<input name="ip_address" placeholder="10.0.1.11" /></label>
          <label>SSH 계정<input name="ssh_username" placeholder="eolwatch" /></label>
          <label>지원종료일<input type="date" name="support_end_date" /></label>
          <label>근거 URL<input type="url" name="lifecycle_source_url" placeholder="https://..." /></label>
          <label className="checkbox"><input type="checkbox" name="monitored" /> SSH 점검 대상</label>
          {error && <p className="form-error">{error}</p>}
          <button className="primary submit" type="submit">저장</button>
        </form>
      )}
      <div className="table-wrap">
        <table>
          <thead><tr><th>자산번호</th><th>자산</th><th>구분</th><th>모델</th><th>연결 정보</th><th>지원 상태</th><th>점검</th></tr></thead>
          <tbody>
            {assets.map((asset) => (
              <tr key={asset.id}>
                <td><code>{asset.asset_tag}</code></td>
                <td><strong>{asset.name}</strong><small>{sites.find((site) => site.id === asset.site_id)?.name || asset.site || '위치 미입력'}</small></td>
                <td>{typeText[asset.asset_type]}</td><td>{asset.manufacturer} {asset.model}</td>
                <td>소프트웨어 {asset.software_count} · SBOM {asset.sbom_count}</td>
                <td><RiskBadge level={asset.risk_level} /> <small>{asset.days_left === null ? '날짜 미입력' : `${asset.days_left}일`}</small></td>
                <td><button className="table-button" disabled={!canEdit || !asset.ip_address || !asset.ssh_username} onClick={async () => {
                  try {
                    const job = await api(`/checks/assets/${asset.id}/run`, { method: 'POST' })
                    onChanged(job.status === 'SUCCESS' ? '인프라 점검을 완료했습니다.' : `점검 실패: ${job.failure_message}`)
                  } catch (reason) { onChanged(reason.message) }
                }}>실행</button></td>
              </tr>
            ))}
            {assets.length === 0 && <tr><td colSpan="7" className="empty">등록된 자산이 없습니다.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function Organization({ customers, sites, onChanged, canEdit }) {
  const [error, setError] = useState('')
  async function createCustomer(event) {
    event.preventDefault(); setError('')
    try {
      await api('/customers', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.fromEntries(new FormData(event.currentTarget))) })
      event.currentTarget.reset(); onChanged('고객사를 등록했습니다.')
    } catch (reason) { setError(reason.message) }
  }
  async function createSite(event) {
    event.preventDefault(); setError('')
    const data = Object.fromEntries(new FormData(event.currentTarget)); data.customer_id = Number(data.customer_id)
    try {
      await api('/sites', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      event.currentTarget.reset(); onChanged('고객 사이트를 등록했습니다.')
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
    event.preventDefault()
    setError('')
    const data = Object.fromEntries(new FormData(event.currentTarget))
    for (const key of ['vendor', 'purl', 'support_end_date', 'lifecycle_source_url', 'asset_id']) if (!data[key]) data[key] = null
    if (data.asset_id) data.asset_id = Number(data.asset_id)
    try {
      await api('/software', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      event.currentTarget.reset()
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

function Sboms({ sboms, assets, onImported, canEdit }) {
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
        <span className="eyebrow">CycloneDX JSON</span><h2>SBOM 가져오기</h2>
        <p>구성요소와 의존관계를 분리 저장하고 품질 항목을 자동 검사합니다.</p>
        <form onSubmit={upload}>
          <label className="file-drop"><input type="file" accept="application/json,.json" onChange={(e) => setFile(e.target.files[0])} /><b>{file ? file.name : 'JSON 파일 선택'}</b><small>CycloneDX 1.4 ~ 1.7</small></label>
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
              <div><strong>{sbom.serial_number.replace('urn:uuid:', '').slice(0, 18)}</strong><small>CycloneDX {sbom.spec_version} · 문서 v{sbom.document_version}</small></div>
              <div className="score"><b>{sbom.quality_score}</b><small>품질 점수</small></div>
              <div className="counts"><span>{sbom.component_count} 구성요소</span><span>{sbom.dependency_count} 의존관계</span></div>
            </div>
          ))}
          {sboms.length === 0 && <p className="empty">가져온 SBOM이 없습니다.</p>}
        </div>
      </article>
    </section>
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
  return <article><b>{title}</b><strong>{items.length}개</strong>{items.slice(0, 5).map((item) => <small key={item.identity}>{item.name} {item.before_version || '-'} → {item.after_version || '-'}</small>)}</article>
}

function Security({ sboms, vulnerabilities, onChanged, canEdit }) {
  const [sbomId, setSbomId] = useState('')
  const [busy, setBusy] = useState(false)
  async function scan() {
    setBusy(true)
    try {
      const result = await api(`/vulnerabilities/scan/sbom/${sbomId}`, { method: 'POST' })
      onChanged(`OSV 조회 완료: 취약점 연결 ${result.vulnerability_links}건`)
    } catch (reason) { onChanged(reason.message, true) }
    finally { setBusy(false) }
  }
  async function updateVex(linkId, status) {
    try {
      await api(`/vulnerabilities/${linkId}/vex`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status }) })
      onChanged('VEX 상태를 변경했습니다.')
    } catch (reason) { onChanged(reason.message, true) }
  }
  return <section className="panel full-panel">
    <div className="panel-heading">
      <div><span className="eyebrow">OSV + VEX</span><h2>소프트웨어 취약점</h2></div>
      <div className="action-row"><select value={sbomId} onChange={(event) => setSbomId(event.target.value)}><option value="">SBOM 선택</option>{sboms.map((item) => <option value={item.id} key={item.id}>#{item.id} · 구성요소 {item.component_count}</option>)}</select><button className="primary" disabled={!canEdit || !sbomId || busy} onClick={scan}>{busy ? '조회 중…' : 'OSV 조회'}</button></div>
    </div>
    <div className="table-wrap"><table><thead><tr><th>OSV ID</th><th>구성요소</th><th>심각도</th><th>요약</th><th>VEX 상태</th></tr></thead>
      <tbody>{vulnerabilities.map((item) => <tr key={item.link_id}><td><code>{item.osv_id}</code><small>{item.aliases.slice(0, 2).join(', ')}</small></td><td><strong>{item.component_name}</strong><small>{item.component_version}</small></td><td><span className={`severity severity-${item.severity.toLowerCase()}`}>{item.severity}</span></td><td>{item.summary || '설명 없음'}</td><td><select value={item.vex_status} disabled={!canEdit} onChange={(event) => updateVex(item.link_id, event.target.value)}><option value="AFFECTED">영향 있음</option><option value="NOT_AFFECTED">영향 없음</option><option value="FIXED">조치 완료</option><option value="UNDER_INVESTIGATION">조사 중</option></select></td></tr>)}{!vulnerabilities.length && <tr><td colSpan="5" className="empty">조회된 취약점이 없습니다. SBOM을 선택해 OSV 조회를 실행하세요.</td></tr>}</tbody>
    </table></div>
  </section>
}

function Operations({ notifications, auditLogs, users, onChanged, canEdit }) {
  async function createUser(event) {
    event.preventDefault()
    try {
      const data = Object.fromEntries(new FormData(event.currentTarget))
      await api('/auth/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      event.currentTarget.reset(); onChanged('사용자 계정을 만들었습니다.')
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
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('eolwatch_user')) }
    catch { return null }
  })
  const [tab, setTab] = useState('overview')
  const [summary, setSummary] = useState(EMPTY_SUMMARY)
  const [assets, setAssets] = useState([])
  const [software, setSoftware] = useState([])
  const [sboms, setSboms] = useState([])
  const [customers, setCustomers] = useState([])
  const [sites, setSites] = useState([])
  const [checks, setChecks] = useState([])
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [notifications, setNotifications] = useState([])
  const [auditLogs, setAuditLogs] = useState([])
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  const canEdit = user?.role === 'ADMIN'
  async function load(message = '', isError = false) {
    try {
      const [nextSummary, nextAssets, nextSoftware, nextSboms, nextCustomers, nextSites, nextChecks, nextVulnerabilities, nextNotifications, nextAuditLogs, nextUsers] = await Promise.all([
        api('/dashboard/summary'), api('/assets'), api('/software'), api('/sboms'), api('/customers'), api('/sites'), api('/checks'), api('/vulnerabilities'), api('/notifications'),
        canEdit ? api('/auth/audit-logs') : Promise.resolve([]), canEdit ? api('/auth/users') : Promise.resolve([]),
      ])
      setSummary(nextSummary); setAssets(nextAssets); setSoftware(nextSoftware); setSboms(nextSboms); setCustomers(nextCustomers); setSites(nextSites); setChecks(nextChecks); setVulnerabilities(nextVulnerabilities); setNotifications(nextNotifications); setAuditLogs(nextAuditLogs); setUsers(nextUsers)
      setError(isError ? message : ''); setMessage(isError ? '' : message)
      if (message) setTimeout(() => setMessage(''), 2500)
    } catch (reason) {
      if (reason.message.includes('로그인') || reason.message.includes('토큰')) logout()
      else setError(`API 연결 실패: ${reason.message}`)
    }
    finally { setLoading(false) }
  }
  function logout() {
    localStorage.removeItem('eolwatch_token'); localStorage.removeItem('eolwatch_user'); setUser(null)
  }
  useEffect(() => { if (user) { setLoading(true); load() } }, [user?.id, user?.role])

  if (!user) return <Login onLogin={setUser} />

  return (
    <div className="app-shell">
      <aside>
        <div className="brand"><span className="brand-mark">E</span><div><strong>EOLWatch</strong><small>Lifecycle Intelligence</small></div></div>
        <nav>
          <button className={tab === 'overview' ? 'active' : ''} onClick={() => setTab('overview')}><span>⌁</span> 통합 현황</button>
          <button className={tab === 'organization' ? 'active' : ''} onClick={() => setTab('organization')}><span>△</span> 고객·사이트</button>
          <button className={tab === 'assets' ? 'active' : ''} onClick={() => setTab('assets')}><span>□</span> 인프라 자산</button>
          <button className={tab === 'software' ? 'active' : ''} onClick={() => setTab('software')}><span>○</span> 인프라 SW</button>
          <button className={tab === 'sbom' ? 'active' : ''} onClick={() => setTab('sbom')}><span>◇</span> SBOM 관리</button>
          <button className={tab === 'security' ? 'active' : ''} onClick={() => setTab('security')}><span>!</span> 취약점·VEX</button>
          <button className={tab === 'checks' ? 'active' : ''} onClick={() => setTab('checks')}><span>✓</span> 점검 이력</button>
          <button className={tab === 'operations' ? 'active' : ''} onClick={() => setTab('operations')}><span>≡</span> 운영·보고서</button>
        </nav>
        <div className="standard-note"><b>{user.username}</b><p>{canEdit ? '관리자' : '조회자'} 권한으로 접속했습니다.</p><button className="logout" onClick={logout}>로그아웃</button></div>
      </aside>
      <main>
        <header><div><span className="eyebrow">INFRASTRUCTURE LIFECYCLE</span><h1>{{ overview: '통합 현황', organization: '고객사와 사이트', assets: '인프라 자산', software: '인프라 소프트웨어', sbom: 'SBOM 관리', security: '취약점과 VEX', checks: '점검 이력', operations: '운영과 보고서' }[tab]}</h1></div><div className="today"><small>기준일</small><strong>{new Intl.DateTimeFormat('ko-KR', { dateStyle: 'long' }).format(new Date())}</strong></div></header>
        {error && <div className="alert error">{error}</div>}
        {message && <div className="alert success">{message}</div>}
        {loading ? <div className="loading">데이터를 불러오는 중입니다…</div> : tab === 'overview' ? <Overview summary={summary} /> : tab === 'organization' ? <Organization customers={customers} sites={sites} onChanged={load} canEdit={canEdit} /> : tab === 'assets' ? <Assets assets={assets} sites={sites} onChanged={load} canEdit={canEdit} /> : tab === 'software' ? <Software software={software} assets={assets} onCreated={load} canEdit={canEdit} /> : tab === 'checks' ? <Checks checks={checks} /> : tab === 'security' ? <Security sboms={sboms} vulnerabilities={vulnerabilities} onChanged={load} canEdit={canEdit} /> : tab === 'operations' ? <Operations notifications={notifications} auditLogs={auditLogs} users={users} onChanged={load} canEdit={canEdit} /> : <Sboms sboms={sboms} assets={assets} onImported={load} canEdit={canEdit} />}
      </main>
    </div>
  )
}
