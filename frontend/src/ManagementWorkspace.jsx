import { useEffect, useRef, useState } from 'react'
import './ManagementWorkspace.css'

const PAGE_SIZE = 20
const productTypes = { HARDWARE_MODEL: '장비 모델', OS: '운영체제', FIRMWARE: '펌웨어', HYPERVISOR: '하이퍼바이저', MIDDLEWARE: '미들웨어', DBMS: 'DBMS', AGENT: '에이전트', LIBRARY: '라이브러리', APPLICATION: '애플리케이션' }
const dates = [['eol_date', 'EOL · 제품 종료일'], ['support_end_date', 'EOSL · 지원종료일'], ['security_end_date', '보안지원 종료일']]
const validUrl = (value) => { try { return ['http:', 'https:'].includes(new URL(value).protocol) } catch { return false } }
const display = (value) => value ?? '미확인'
const sourceLink = (value) => value && validUrl(value) ? <a href={value} target="_blank" rel="noreferrer">{value}</a> : value || '미입력'

function useRead(path, request) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [revision, setRevision] = useState(0)
  const [readPath, setReadPath] = useState(null)
  useEffect(() => {
    const controller = new AbortController()
    setLoading(true); setError(''); setData(null); setReadPath(path)
    if (!path) { setLoading(false); return () => controller.abort() }
    request(path, { signal: controller.signal }).then((value) => { if (!controller.signal.aborted) setData(value) })
      .catch((err) => { if (!controller.signal.aborted) setError(err.message) })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [path, request, revision])
  return { data: readPath === path ? data : null, error: readPath === path ? error : '', loading: readPath !== path || loading, refresh: () => setRevision((value) => value + 1) }
}

function Pages({ page, hasMore, loading, onPage }) {
  return <div className="management-pages"><button type="button" className="secondary" disabled={loading || page === 0} onClick={() => onPage(page - 1)}>이전 페이지</button><span>{page + 1} 페이지</span><button type="button" className="secondary" disabled={loading || !hasMore} onClick={() => onPage(page + 1)}>다음 페이지</button></div>
}

function ReadState({ read, name }) {
  return <>{read.loading && <p role="status">{name} 불러오는 중…</p>}{read.error && <div role="alert" className="form-error">{name} 조회 실패: {read.error} <button type="button" className="secondary" onClick={read.refresh}>다시 불러오기</button></div>}</>
}

function ProductDetails({ productId, canEdit, request, onSaved, onClose, onViewAsset }) {
  const product = useRead(`/products/${productId}`, request)
  const impact = useRead(`/products/${productId}/impact`, request)
  const [draft, setDraft] = useState(null)
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const [page, setPage] = useState(0)
  const busy = useRef(false)
  const mutation = useRef(null)
  useEffect(() => { if (product.data) setDraft(Object.fromEntries([...dates.map(([key]) => key), 'lifecycle_source_url'].map((key) => [key, product.data[key] || '']))) }, [product.data])
  useEffect(() => () => mutation.current?.abort(), [])
  async function save(event) {
    event.preventDefault()
    if (busy.current || !canEdit || !draft || !product.data) return
    if (dates.some(([key]) => draft[key]) && !draft.lifecycle_source_url.trim()) { setError('수명주기 날짜에는 공식 근거 URL을 입력하세요.'); return }
    if (draft.lifecycle_source_url && !validUrl(draft.lifecycle_source_url)) { setError('근거 URL은 http 또는 https 주소여야 합니다.'); return }
    const values = Object.fromEntries(Object.entries(draft).map(([key, value]) => [key, value.trim() || null]).filter(([key, value]) => value !== (product.data[key] || null)))
    busy.current = true; setPending(true); setError('')
    const controller = new AbortController(); mutation.current = controller
    try {
      await request(`/products/${productId}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(values), signal: controller.signal })
      if (!controller.signal.aborted) onSaved('제품 수명주기 정보를 저장했습니다.')
    } catch (err) { if (!controller.signal.aborted) setError(`제품 정보를 저장하지 못했습니다. ${err.message}`) }
    finally { if (!controller.signal.aborted) { busy.current = false; setPending(false) } }
  }
  const item = product.data
  const affected = impact.data?.affected_assets || []
  return <section className="management-detail" aria-label="제품 수명주기 상세"><div className="management-heading"><h3>{item ? `${item.name} ${item.version}` : '제품 상세'}</h3><button type="button" className="secondary" disabled={pending} onClick={onClose}>제품 상세 닫기</button></div>
    <ReadState read={product} name="제품" />
    {item && <><dl className="management-info"><dt>유형 / 제조사</dt><dd>{productTypes[item.product_type] || item.product_type} · {item.vendor || '미입력'}</dd><dt>PURL</dt><dd>{item.purl || '미입력'}</dd><dt>CPE</dt><dd>{item.cpe || '미입력'}</dd><dt>수동 입력 시각</dt><dd>{item.verified_at ? new Date(item.verified_at).toLocaleString('ko-KR') : '미입력'}</dd></dl><p className="workspace-help">수동 입력 시각은 외부 공지 내용을 검증한 시각을 뜻하지 않습니다. 공개 일정 수집·적용 근거는 EOL 일정 조회에서 확인하세요.</p>
      <p className="management-note">위험도는 보안지원 종료일 → 지원종료일 → EOL 순서로 적용합니다. 개별 날짜를 지정한 구성요소는 그 값을 유지하고, 나머지 구성요소는 제품 날짜를 상속합니다.</p>
      {canEdit && draft ? <form onSubmit={save}><fieldset disabled={pending} className="management-form">{dates.map(([key, label]) => <label key={key}>{label}<input type="date" value={draft[key]} onChange={(e) => setDraft((previous) => ({ ...previous, [key]: e.target.value }))} /></label>)}<label className="management-wide">공식 근거 URL<input type="url" value={draft.lifecycle_source_url} onChange={(e) => setDraft((previous) => ({ ...previous, lifecycle_source_url: e.target.value }))} placeholder="https://" /></label></fieldset>{error && <p role="alert" className="form-error">{error}</p>}<button type="submit" className="primary" disabled={pending}>{pending ? '저장 중…' : '제품 날짜 저장'}</button></form> : <dl className="management-info">{dates.map(([key, label]) => <div key={key}><dt>{label}</dt><dd>{display(item[key])}</dd></div>)}<dt>공식 근거 URL</dt><dd>{sourceLink(item.lifecycle_source_url)}</dd></dl>}
    </>}
    <h4>영향 자산 {impact.data ? `· ${impact.data.asset_count}대` : ''}</h4><p className="management-note">장비 모델·설치 제품·전체 SBOM 이력에 연결된 자산입니다. 현재 설치 여부는 최신 분석과 함께 확인하세요.</p><ReadState read={impact} name="영향 자산" />
    {!impact.loading && !impact.error && !affected.length && <p>연결된 자산이 없습니다.</p>}
    {!!affected.length && <><ul className="management-impact">{affected.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((asset) => <li key={asset.id}><span><strong>{asset.asset_tag}</strong> · {asset.name} · {asset.ip_address || 'IP 미입력'}</span><button type="button" className="table-button" onClick={() => onViewAsset(asset.id)}>자산 보기</button></li>)}</ul><Pages page={page} hasMore={affected.length > (page + 1) * PAGE_SIZE} onPage={setPage} /></>}
  </section>
}

function ContractEditor({ contractId, customers, assets, sites, canEdit, request, onSaved, onClose }) {
  const read = useRead(contractId ? `/contracts/${contractId}` : null, request)
  const blank = { customer_id: '', contract_no: '', provider: '', start_date: '', end_date: '', annual_cost: '', service_level: '', asset_ids: [] }
  const [draft, setDraft] = useState(blank)
  const [baseline, setBaseline] = useState(blank)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const busy = useRef(false)
  const mutation = useRef(null)
  useEffect(() => { if (read.data) { const values = Object.fromEntries(Object.keys(blank).map((key) => [key, read.data[key] ?? ''])); setDraft(values); setBaseline(values) } }, [read.data])
  useEffect(() => () => mutation.current?.abort(), [])
  const eligible = (asset) => sites.find((site) => site.id === asset.site_id)?.customer_id === Number(draft.customer_id)
  const change = (key, value) => { setDraft((previous) => ({ ...previous, [key]: value })); setError('') }
  async function save(event) {
    event.preventDefault()
    if (!canEdit || busy.current || (contractId && !read.data)) return
    if (!draft.customer_id || !draft.contract_no.trim() || !draft.provider.trim() || !draft.start_date || !draft.end_date) { setError('고객사, 계약번호, 유지보수사, 계약 기간을 입력하세요.'); return }
    if (draft.end_date < draft.start_date) { setError('계약 종료일은 시작일보다 빠를 수 없습니다.'); return }
    if (draft.asset_ids.some((id) => !assets.some((asset) => asset.id === id && eligible(asset)))) { setError('계약 자산은 선택한 고객사의 사이트에 연결되어 있어야 합니다.'); return }
    if (draft.annual_cost !== '' && (!Number.isFinite(Number(draft.annual_cost)) || Number(draft.annual_cost) < 0 || Number(draft.annual_cost) >= 1000000000000)) { setError('연간 비용은 0 이상 1조 미만의 금액으로 입력하세요.'); return }
    const normalize = (key, value) => key === 'asset_ids' ? [...value].sort((a, b) => a - b) : ['customer_id', 'annual_cost'].includes(key) ? value === '' ? null : Number(value) : value.trim() || null
    const values = Object.fromEntries(Object.entries(draft).map(([key, value]) => [key, normalize(key, value)]).filter(([key, value]) => !contractId || JSON.stringify(value) !== JSON.stringify(normalize(key, baseline[key]))))
    busy.current = true; setPending(true); setError('')
    const controller = new AbortController(); mutation.current = controller
    try {
      await request(contractId ? `/contracts/${contractId}` : '/contracts', { method: contractId ? 'PATCH' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(values), signal: controller.signal })
      if (!controller.signal.aborted) onSaved(contractId ? '계약 변경을 저장했습니다.' : '계약을 등록했습니다.')
    } catch (err) { if (!controller.signal.aborted) setError(`계약을 저장하지 못했습니다. ${err.message}`) }
    finally { if (!controller.signal.aborted) { busy.current = false; setPending(false) } }
  }
  return <section className="management-detail" aria-label="계약 상세"><div className="management-heading"><h3>{contractId ? '계약 상세' : '계약 등록'}</h3><button type="button" className="secondary" disabled={pending} onClick={onClose}>계약 상세 닫기</button></div>{contractId && <ReadState read={read} name="계약" />}
    {canEdit ? <form onSubmit={save}><fieldset disabled={pending || Boolean(contractId && !read.data)} className="management-form">
      <label>계약 고객사<select required value={draft.customer_id} onChange={(e) => change('customer_id', e.target.value)}><option value="">고객사 선택</option>{customers.map((customer) => <option key={customer.id} value={customer.id}>{customer.name}</option>)}</select></label>
      <label>계약번호<input required maxLength={80} value={draft.contract_no} onChange={(e) => change('contract_no', e.target.value)} /></label><label>유지보수사<input required maxLength={160} value={draft.provider} onChange={(e) => change('provider', e.target.value)} /></label>
      <label>계약 시작일<input type="date" required value={draft.start_date} onChange={(e) => change('start_date', e.target.value)} /></label><label>계약 종료일<input type="date" required value={draft.end_date} onChange={(e) => change('end_date', e.target.value)} /></label><label>연간 비용 (원)<input type="number" min="0" max="999999999999.99" step="0.01" value={draft.annual_cost} onChange={(e) => change('annual_cost', e.target.value)} /></label><label>서비스 수준<input maxLength={100} placeholder="예: 24x7" value={draft.service_level} onChange={(e) => change('service_level', e.target.value)} /></label>
      <fieldset className="management-wide management-assets"><legend>계약 자산</legend><p>선택한 고객사 소속 사이트의 자산만 연결할 수 있습니다. 고객사를 변경하면 기존 선택도 다시 확인하세요.</p>{assets.filter((asset) => eligible(asset) || draft.asset_ids.includes(asset.id)).map((asset) => <label key={asset.id} className="management-check"><input type="checkbox" checked={draft.asset_ids.includes(asset.id)} onChange={(e) => change('asset_ids', e.target.checked ? [...draft.asset_ids, asset.id] : draft.asset_ids.filter((id) => id !== asset.id))} />{asset.asset_tag} · {asset.name}{!eligible(asset) ? ' (고객사 불일치 · 선택 해제 필요)' : ''}</label>)}{!assets.some(eligible) && <p>이 고객사에 연결 가능한 자산이 없습니다. 자산 관리에서 사이트를 연결할 수 있습니다.</p>}</fieldset>
    </fieldset>{error && <p role="alert" className="form-error">{error}</p>}<button type="submit" className="primary" disabled={pending || Boolean(contractId && !read.data)}>{pending ? '저장 중…' : contractId ? '계약 변경 저장' : '계약 등록 저장'}</button></form> : read.data && <dl className="management-info"><dt>계약번호</dt><dd>{read.data.contract_no}</dd><dt>고객사 / 유지보수사</dt><dd>{read.data.customer_name} · {read.data.provider}</dd><dt>계약 기간</dt><dd>{read.data.start_date} ~ {read.data.end_date}</dd><dt>연간 비용</dt><dd>{read.data.annual_cost == null ? '미입력' : `${Number(read.data.annual_cost).toLocaleString('ko-KR')}원`}</dd><dt>서비스 수준</dt><dd>{read.data.service_level || '미입력'}</dd><dt>계약 자산</dt><dd>{read.data.asset_ids.map((id) => assets.find((asset) => asset.id === id)?.asset_tag || `자산 #${id}`).join(', ') || '연결 없음'}</dd></dl>}
  </section>
}

export default function ManagementWorkspace({ assets = [], customers = [], sites = [], canEdit, request, onChanged, onViewAsset }) {
  const [tab, setTab] = useState('products')
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('')
  const [search, setSearch] = useState({ q: '', filter: '' })
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState(null)
  const params = new URLSearchParams({ limit: String(PAGE_SIZE + 1), offset: String(page * PAGE_SIZE) })
  if (search.q) params.set('q', search.q)
  if (search.filter) params.set(tab === 'products' ? 'product_type' : 'customer_id', search.filter)
  const read = useRead(`/${tab}?${params}`, request)
  const rows = read.data || []
  function switchTab(value) { setTab(value); setQuery(''); setFilter(''); setSearch({ q: '', filter: '' }); setPage(0); setSelected(null) }
  function saved(message) { setSelected(null); read.refresh(); onChanged(message) }
  return <section className="management-workspace panel" aria-label="제품 및 계약 관리"><h2>제품 · 계약 관리</h2><p>공통 제품 수명주기와 유지보수 계약을 관리합니다.</p>
    <div className="management-tabs" role="tablist" aria-label="관리 종류"><button type="button" role="tab" aria-selected={tab === 'products'} onClick={() => switchTab('products')}>제품 수명주기</button><button type="button" role="tab" aria-selected={tab === 'contracts'} onClick={() => switchTab('contracts')}>유지보수 계약</button></div>
    <form className="management-search" onSubmit={(e) => { e.preventDefault(); setSearch({ q: query.trim(), filter }); setPage(0); setSelected(null); read.refresh() }}>
      <label>{tab === 'products' ? '제품 검색어' : '계약 검색어'}<input maxLength={100} value={query} onChange={(e) => setQuery(e.target.value)} placeholder={tab === 'products' ? '제품명, 제조사, 버전, PURL, CPE' : '계약번호, 유지보수사, 고객사'} /></label>
      <label>{tab === 'products' ? '제품 유형' : '고객사 필터'}<select value={filter} onChange={(e) => setFilter(e.target.value)}><option value="">전체</option>{tab === 'products' ? Object.entries(productTypes).map(([value, label]) => <option key={value} value={value}>{label}</option>) : customers.map((customer) => <option key={customer.id} value={customer.id}>{customer.name}</option>)}</select></label><button className="primary" type="submit">검색</button>{tab === 'contracts' && canEdit && <button type="button" className="secondary" onClick={() => setSelected('new')}>계약 등록</button>}
    </form>
    {selected !== null && (tab === 'products' ? <ProductDetails key={`p${selected}`} productId={selected} canEdit={canEdit} request={request} onSaved={saved} onClose={() => setSelected(null)} onViewAsset={onViewAsset} /> : <ContractEditor key={`c${selected}`} contractId={selected === 'new' ? null : selected} customers={customers} assets={assets} sites={sites} canEdit={canEdit} request={request} onSaved={saved} onClose={() => setSelected(null)} />)}
    <ReadState read={read} name={tab === 'products' ? '제품 목록' : '계약 목록'} />
    {!read.loading && !read.error && !rows.length && <p>검색 결과가 없습니다.</p>}
    {!!rows.length && <div className="table-wrap"><table><thead>{tab === 'products' ? <tr><th>제품 / 버전</th><th>유형 / 제조사</th><th>EOL</th><th>EOSL</th><th>보안지원 종료</th><th>위험도</th><th>상세</th></tr> : <tr><th>계약번호 / 고객사</th><th>유지보수사</th><th>계약 기간</th><th>연간 비용</th><th>자산 수</th><th>위험도</th><th>상세</th></tr>}</thead><tbody>{rows.slice(0, PAGE_SIZE).map((item) => tab === 'products' ? <tr key={item.id}><td><strong>{item.name}</strong><small>{item.version}</small></td><td>{productTypes[item.product_type] || item.product_type}<small>{item.vendor || '미입력'}</small></td><td>{display(item.eol_date)}</td><td>{display(item.support_end_date)}</td><td>{display(item.security_end_date)}</td><td>{item.risk_level}</td><td><button type="button" className="table-button" onClick={() => setSelected(item.id)}>제품 상세</button></td></tr> : <tr key={item.id}><td><strong>{item.contract_no}</strong><small>{item.customer_name}</small></td><td>{item.provider}</td><td>{item.start_date}<br />~ {item.end_date}</td><td>{item.annual_cost == null ? '미입력' : `${Number(item.annual_cost).toLocaleString('ko-KR')}원`}</td><td>{item.asset_ids.length}</td><td>{item.risk_level}</td><td><button type="button" className="table-button" onClick={() => setSelected(item.id)}>계약 상세</button></td></tr>)}</tbody></table></div>}
    <Pages page={page} hasMore={rows.length > PAGE_SIZE} loading={read.loading} onPage={(value) => { setPage(value); setSelected(null) }} />
  </section>
}
