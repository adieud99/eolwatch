import { useEffect, useRef, useState } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import './AssetEditor.css'

const types = { server: '서버', storage: '스토리지', network: '네트워크', security: '보안', vm: '가상머신', cloud: '클라우드', other: '기타' }
const textFields = [['manufacturer', '제조사'], ['model', '모델명'], ['serial_number', '시리얼 번호'], ['site', '설치 위치 메모'], ['building', '건물'], ['floor', '층'], ['room', '전산실'], ['rack', '랙 번호'], ['rack_position', '랙 위치'], ['ip_address', 'IP 주소 / 호스트'], ['ssh_username', 'SSH 사용자명'], ['power_source', '전력 데이터 출처'], ['owner_name', '담당자'], ['owner_department', '담당 부서']]
const editable = ['asset_tag', 'name', 'asset_type', 'site_id', 'model_release_id', ...textFields.map(([key]) => key), 'ssh_port', 'introduced_on', 'purchase_date', 'purchase_price', 'power_watts', 'warranty_end_date', 'operational_status', 'service_criticality', 'support_end_date', 'lifecycle_source_url', 'monitored']
const draftOf = (asset) => Object.fromEntries(editable.map((key) => [key, key === 'monitored' ? Boolean(asset[key]) : asset[key] ?? (key === 'ssh_port' ? 22 : '')]))
const normalize = (key, value) => key === 'monitored' ? value : ['site_id', 'model_release_id', 'ssh_port', 'purchase_price', 'power_watts'].includes(key) ? value === '' ? null : Number(value) : typeof value === 'string' ? value.trim() || null : value
const validUrl = (value) => { try { return ['http:', 'https:'].includes(new URL(value).protocol) } catch { return false } }

export default function AssetEditor({ asset, sites = [], canEdit, request, onSaved, onClose, onViewCve, onViewSbom, onViewManagement }) {
  const [current, setCurrent] = useState(asset)
  const [draft, setDraft] = useState(() => draftOf(asset))
  const [ready, setReady] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const [retry, setRetry] = useState(0)
  const [models, setModels] = useState([])
  const [modelQuery, setModelQuery] = useState('')
  const [modelSearch, setModelSearch] = useState('')
  const [modelRevision, setModelRevision] = useState(0)
  const [modelError, setModelError] = useState('')
  const [modelLoading, setModelLoading] = useState(false)
  const [timeline, setTimeline] = useState([])
  const [software, setSoftware] = useState([])
  const [sboms, setSboms] = useState([])
  const [detailTab, setDetailTab] = useState('overview')
  const [contracts, setContracts] = useState([])
  const [riskHistory, setRiskHistory] = useState([])
  const [riskSaving, setRiskSaving] = useState(false)
  const [qrOpen, setQrOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [confirmation, setConfirmation] = useState('')
  const busy = useRef(false)
  const mutation = useRef(null)

  useEffect(() => {
    const controller = new AbortController()
    setReady(false); setLoading(true); setPending(false); setError(''); setDeleteOpen(false); setConfirmation('')
    request(`/assets/${asset.id}`, { signal: controller.signal }).then((fresh) => {
      if (!controller.signal.aborted) { setCurrent(fresh); setDraft(draftOf(fresh)); setReady(true) }
    }).catch((err) => { if (!controller.signal.aborted) setError(`자산 정보를 불러오지 못했습니다. ${err.message}`) })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    request(`/assets/${asset.id}/timeline`, { signal: controller.signal }).then((events) => {
      if (!controller.signal.aborted && Array.isArray(events)) setTimeline(events)
    }).catch(() => {})
    request('/software', { signal: controller.signal }).then((items) => {
      if (!controller.signal.aborted && Array.isArray(items)) setSoftware(items.filter((item) => item.asset_ids?.includes(asset.id)))
    }).catch(() => {})
    request('/sboms', { signal: controller.signal }).then((items) => {
      if (!controller.signal.aborted && Array.isArray(items)) setSboms(items.filter((item) => item.asset_id === asset.id))
    }).catch(() => {})
    request('/contracts', { signal: controller.signal }).then((items) => {
      if (!controller.signal.aborted && Array.isArray(items)) setContracts(items.filter((item) => item.asset_ids?.includes(asset.id)))
    }).catch(() => {})
    request(`/assets/${asset.id}/risk-snapshots`, { signal: controller.signal }).then((items) => {
      if (!controller.signal.aborted && Array.isArray(items)) setRiskHistory(items)
    }).catch(() => {})
    setDetailTab('overview')
    return () => { controller.abort(); mutation.current?.abort(); busy.current = false }
  }, [asset.id, request, retry])

  useEffect(() => {
    if (!canEdit) return
    const controller = new AbortController()
    setModelLoading(true); setModelError('')
    const params = new URLSearchParams({ product_type: 'HARDWARE_MODEL', limit: '21', offset: '0' })
    if (modelSearch) params.set('q', modelSearch)
    request(`/products?${params}`, { signal: controller.signal }).then((items) => {
      if (!controller.signal.aborted) setModels(items)
    }).catch((err) => { if (!controller.signal.aborted) setModelError(`장비 모델을 불러오지 못했습니다. ${err.message}`) })
      .finally(() => { if (!controller.signal.aborted) setModelLoading(false) })
    return () => controller.abort()
  }, [request, canEdit, modelSearch, modelRevision])

  function change(key, value) { setDraft((previous) => ({ ...previous, [key]: value })); setError('') }

  async function save(event) {
    event.preventDefault()
    if (!canEdit || !ready || busy.current) return
    if (!draft.asset_tag.trim() || !draft.name.trim()) { setError('자산번호와 자산명을 입력하세요.'); return }
    if (!Number.isInteger(Number(draft.ssh_port)) || Number(draft.ssh_port) < 1 || Number(draft.ssh_port) > 65535) { setError('SSH 포트는 1~65535 사이 정수여야 합니다.'); return }
    if (draft.support_end_date && !draft.lifecycle_source_url.trim()) { setError('지원종료일의 근거 URL을 입력하세요.'); return }
    if (draft.lifecycle_source_url && !validUrl(draft.lifecycle_source_url)) { setError('근거 URL은 http 또는 https 주소여야 합니다.'); return }
    const values = Object.fromEntries(editable.map((key) => [key, normalize(key, draft[key])]).filter(([key, value]) => value !== normalize(key, current[key] ?? (key === 'monitored' ? false : ''))))
    busy.current = true; setPending(true); setError('')
    const controller = new AbortController(); mutation.current = controller
    try {
      const updated = await request(`/assets/${asset.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(values), signal: controller.signal })
      if (!controller.signal.aborted) onSaved(updated)
    } catch (err) { if (!controller.signal.aborted) setError(`자산을 저장하지 못했습니다. ${err.message}`) }
    finally { if (!controller.signal.aborted) { busy.current = false; setPending(false) } }
  }

  async function remove(event) {
    event.preventDefault()
    if (!canEdit || !ready || busy.current || confirmation !== current.asset_tag) return
    busy.current = true; setPending(true); setError('')
    const controller = new AbortController(); mutation.current = controller
    try {
      await request(`/assets/${asset.id}`, { method: 'DELETE', signal: controller.signal })
      if (!controller.signal.aborted) onSaved(null)
    } catch (err) { if (!controller.signal.aborted) setError(`자산을 삭제하지 못했습니다. ${err.message}`) }
    finally { if (!controller.signal.aborted) { busy.current = false; setPending(false) } }
  }
  async function saveRiskSnapshot() {
    if (riskSaving) return
    setRiskSaving(true)
    try {
      const snapshot = await request(`/assets/${asset.id}/risk-snapshots`, { method: 'POST' })
      setRiskHistory((currentHistory) => [snapshot, ...currentHistory])
    } catch (reason) { setError(`위험도 이력을 저장하지 못했습니다. ${reason.message}`) }
    finally { setRiskSaving(false) }
  }
  async function downloadAssetReport() {
    try {
      const token = localStorage.getItem('eolwatch_token')
      const response = await fetch(`/api/reports/assets/${asset.id}.pdf`, { headers: { Authorization: `Bearer ${token}` } })
      if (!response.ok) throw new Error('자산 보고서를 만들지 못했습니다.')
      const url = URL.createObjectURL(await response.blob())
      const anchor = document.createElement('a')
      anchor.href = url; anchor.download = `eolwatch-asset-${asset.id}.pdf`; anchor.click(); URL.revokeObjectURL(url)
    } catch (reason) { setError(`자산 보고서 다운로드 실패: ${reason.message}`) }
  }
  const detailUrl = `${window.location.origin}/?asset=${asset.id}`
  const monthlyPowerCost = current.power_watts == null ? null : current.power_watts * 24 * 30 / 1000 * 150
  const annualMaintenanceCost = contracts.reduce((total, item) => total + (Number(item.annual_cost) || 0), 0)
  const navigate = (target, value) => {
    const callback = target === 'cve' ? onViewCve : target === 'sbom' ? onViewSbom : target === 'management' ? onViewManagement : null
    if (callback) callback(value)
    else window.dispatchEvent(new CustomEvent('eolwatch-navigate', { detail: { target, value } }))
  }

  return <section className="asset-editor panel" aria-label="자산 정보 관리">
    <div className="asset-editor-heading"><h3>{current.asset_tag} · 자산 정보</h3><button type="button" className="secondary" disabled={pending} onClick={onClose}>닫기</button></div>
    {loading && <p role="status">최신 자산 정보를 불러오는 중입니다.</p>}
    {error && <p role="alert" className="form-error">{error}</p>}
    {!ready && !loading && <button type="button" className="secondary" onClick={() => setRetry((value) => value + 1)}>자산 정보 다시 불러오기</button>}
    <nav className="asset-detail-tabs" aria-label="자산 상세 탭"><button type="button" className={detailTab === 'overview' ? 'active' : ''} onClick={() => setDetailTab('overview')}>기본 정보</button><button type="button" className={detailTab === 'software' ? 'active' : ''} onClick={() => setDetailTab('software')}>소프트웨어 ({software.length})</button><button type="button" className={detailTab === 'sbom' ? 'active' : ''} onClick={() => setDetailTab('sbom')}>SBOM ({sboms.length})</button><button type="button" className={detailTab === 'timeline' ? 'active' : ''} onClick={() => setDetailTab('timeline')}>타임라인 ({timeline.length})</button></nav>
    {detailTab === 'overview' && !canEdit && <dl className="asset-editor-read"><dt>자산명</dt><dd>{current.name}</dd><dt>유형</dt><dd>{types[current.asset_type] || current.asset_type}</dd><dt>사이트</dt><dd>{sites.find((site) => site.id === current.site_id)?.name || '미연결'}</dd>{textFields.map(([key, label]) => <div key={key}><dt>{label}</dt><dd>{current[key] || '미입력'}</dd></div>)}<dt>장비 모델 연결</dt><dd>{current.model_release_id ? `제품 #${current.model_release_id}` : '미연결'}</dd><dt>SSH 포트</dt><dd>{current.ssh_port}</dd><dt>도입일</dt><dd>{current.introduced_on || '미입력'}</dd><dt>구매일</dt><dd>{current.purchase_date || '미입력'}</dd><dt>구매가격</dt><dd>{current.purchase_price == null ? '미입력' : `${Number(current.purchase_price).toLocaleString('ko-KR')}원`}</dd><dt>전력 사용량</dt><dd>{current.power_watts == null ? '미입력' : `${current.power_watts}W`}</dd><dt>보증종료일</dt><dd>{current.warranty_end_date || '미입력'}</dd><dt>운영 상태</dt><dd>{current.operational_status}</dd><dt>서비스 중요도</dt><dd>{current.service_criticality}</dd><dt>지원종료일</dt><dd>{current.support_end_date || '미확인'}</dd><dt>수명주기 근거 URL</dt><dd>{current.lifecycle_source_url && validUrl(current.lifecycle_source_url) ? <a href={current.lifecycle_source_url} target="_blank" rel="noreferrer">{current.lifecycle_source_url}</a> : current.lifecycle_source_url || '미입력'}</dd><dt>모니터링</dt><dd>{current.monitored ? '사용' : '해제'}</dd></dl>}
    {detailTab === 'overview' && <div className="asset-summary"><strong>{current.name}</strong><span>{current.model || '모델 미입력'} · {current.serial_number || '시리얼 미입력'}</span><span>위험도 {current.risk_score ?? 0}점 · {current.priority_level || 'LOW'} · CVE {current.vulnerability_count ?? 0}건</span><span>월 예상 전력비 {monthlyPowerCost == null ? '미입력' : `${Math.round(monthlyPowerCost).toLocaleString('ko-KR')}원`} · 연간 유지보수비 {contracts.length ? `${Math.round(annualMaintenanceCost).toLocaleString('ko-KR')}원` : '미연결'}</span><div className="action-row"><button type="button" className="table-button" onClick={() => navigate('cve', asset.id)}>CVE 조치 보기</button><button type="button" className="table-button" onClick={() => navigate('sbom', sboms[0]?.id)}>SBOM 보기</button><button type="button" className="table-button" onClick={() => navigate('management', asset.id)}>제품·계약 보기</button><button type="button" className="table-button" onClick={() => setQrOpen((value) => !value)}>QR {qrOpen ? '닫기' : '열기'}</button><button type="button" className="table-button" onClick={downloadAssetReport}>자산 PDF</button>{canEdit && <button type="button" className="table-button" disabled={riskSaving} onClick={saveRiskSnapshot}>{riskSaving ? '저장 중…' : '위험도 이력 저장'}</button>}</div>{qrOpen && <div className="asset-qr"><QRCodeSVG value={detailUrl} size={144} includeMargin /><small>현장 조회 주소<br />{detailUrl}</small></div>}</div>}
    {detailTab === 'software' && <section className="asset-related"><h4>설치 소프트웨어</h4>{software.length ? <><div className="asset-relation-map"><strong>{current.name}</strong><span>→</span><div>{software.map((item) => <b key={item.id}>{item.name} {item.version}</b>)}</div></div><ul>{software.map((item) => <li key={item.id}><strong>{item.name}</strong> {item.version}<small>{item.vendor || '공급사 미입력'} · {item.product_type}</small></li>)}</ul></> : <p>연결된 설치 소프트웨어가 없습니다.</p>}</section>}
    {detailTab === 'sbom' && <section className="asset-related"><h4>SBOM 원장</h4>{sboms.length ? <ul>{sboms.map((item) => <li key={item.id}><strong>SBOM #{item.id}</strong><span>{item.bom_format} {item.spec_version} · 구성요소 {item.component_count}개 · 의존관계 {item.dependency_count}개</span><small>{item.imported_at ? new Date(item.imported_at).toLocaleString('ko-KR') : '저장 시각 미기록'}</small><button type="button" className="table-button" onClick={() => onViewSbom?.(item.id)}>SBOM 상세</button></li>)}</ul> : <p>연결된 SBOM이 없습니다.</p>}</section>}
    {detailTab === 'overview' && contracts.length > 0 && <p className="asset-related-note">연결 계약: {contracts.map((item) => `${item.contract_no} (${item.provider})`).join(', ')} <button type="button" className="table-button" onClick={() => navigate('management', asset.id)}>계약 관리</button></p>}
    {riskHistory.length > 0 && <section className="asset-risk-history"><h4>위험도 계산 이력</h4><ul>{riskHistory.slice(0, 5).map((item) => <li key={item.id}><strong>{item.score}점 · {item.priority_level}</strong><small>{new Date(item.calculated_at).toLocaleString('ko-KR')}</small></li>)}</ul></section>}
    {canEdit && !deleteOpen && <form onSubmit={save}>
      <fieldset disabled={!ready || pending} className="asset-editor-grid">
        <label>자산번호<input value={draft.asset_tag} maxLength={80} required onChange={(e) => change('asset_tag', e.target.value)} /></label>
        <label>자산명<input value={draft.name} maxLength={160} required onChange={(e) => change('name', e.target.value)} /></label>
        <label>자산 유형<select value={draft.asset_type} onChange={(e) => change('asset_type', e.target.value)}>{Object.entries(types).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
        <label>고객사 / 사이트<select value={draft.site_id} onChange={(e) => change('site_id', e.target.value)}><option value="">미연결</option>{sites.map((site) => <option key={site.id} value={site.id}>{site.customer_name ? `${site.customer_name} · ` : ''}{site.name}</option>)}</select></label>
        {textFields.map(([key, label]) => <label key={key}>{label}<input value={draft[key]} maxLength={key === 'ssh_username' ? 80 : key === 'ip_address' ? 64 : key === 'manufacturer' ? 120 : 160} onChange={(e) => change(key, e.target.value)} /></label>)}
        <label>SSH 포트<input type="number" min="1" max="65535" step="1" required value={draft.ssh_port} onChange={(e) => change('ssh_port', e.target.value)} /></label>
        <label>도입일<input type="date" value={draft.introduced_on} onChange={(e) => change('introduced_on', e.target.value)} /></label>
        <label>구매일<input type="date" value={draft.purchase_date} onChange={(e) => change('purchase_date', e.target.value)} /></label>
        <label>구매가격 (원)<input type="number" min="0" step="0.01" value={draft.purchase_price} onChange={(e) => change('purchase_price', e.target.value)} /></label>
        <label>전력 사용량 (W)<input type="number" min="0" step="0.1" value={draft.power_watts} onChange={(e) => change('power_watts', e.target.value)} /></label>
        <label>보증종료일<input type="date" value={draft.warranty_end_date} onChange={(e) => change('warranty_end_date', e.target.value)} /></label>
        <label>운영 상태<select value={draft.operational_status} onChange={(e) => change('operational_status', e.target.value)}><option value="ACTIVE">운영 중</option><option value="STANDBY">예비</option><option value="REPAIR">수리 중</option><option value="RETIRING">폐기 예정</option><option value="RETIRED">폐기 완료</option></select></label>
        <label>서비스 중요도<select value={draft.service_criticality} onChange={(e) => change('service_criticality', e.target.value)}><option value="LOW">낮음</option><option value="STANDARD">보통</option><option value="HIGH">높음</option><option value="CRITICAL">핵심</option></select></label>
        <label>지원종료일<input type="date" value={draft.support_end_date} onChange={(e) => change('support_end_date', e.target.value)} /></label>
        <label>수명주기 근거 URL<input type="url" value={draft.lifecycle_source_url} onChange={(e) => change('lifecycle_source_url', e.target.value)} placeholder="https://" /></label>
        <label className="asset-editor-check"><input type="checkbox" checked={draft.monitored} onChange={(e) => change('monitored', e.target.checked)} />모니터링 사용</label>
        <div className="asset-editor-wide"><div className="asset-editor-heading"><label>장비 모델 검색<input value={modelQuery} maxLength={100} onChange={(e) => setModelQuery(e.target.value)} placeholder="제조사 또는 모델명" /></label><button type="button" className="secondary" disabled={modelLoading} onClick={() => { setModelSearch(modelQuery.trim()); setModelRevision((value) => value + 1) }}>모델 검색</button></div>
          {modelError && <p role="alert">{modelError}</p>}
          <label>장비 모델 연결<select value={draft.model_release_id} onChange={(e) => change('model_release_id', e.target.value)}><option value="">미연결</option>{draft.model_release_id && !models.slice(0, 20).some((item) => item.id === Number(draft.model_release_id)) && <option value={draft.model_release_id}>연결된 제품 #{draft.model_release_id}</option>}{models.slice(0, 20).map((item) => <option key={item.id} value={item.id}>{item.vendor ? `${item.vendor} · ` : ''}{item.name} {item.version}</option>)}</select></label>
          {models.length > 20 && <p>검색 결과가 많습니다. 모델명을 구체적으로 입력하세요.</p>}
          <p className="asset-editor-note">연결된 장비 모델에 지원 날짜가 있으면 자산 위험도에 우선 적용됩니다. 제품 관리에서 공통 날짜를 수정할 수 있습니다.</p>
        </div>
      </fieldset>
      <div className="asset-editor-heading"><button type="submit" className="primary" disabled={!ready || pending}>{pending ? '저장 중…' : '자산 변경 저장'}</button><button type="button" className="secondary" disabled={!ready || pending} onClick={() => { setDeleteOpen(true); setError('') }}>자산 삭제…</button></div>
    </form>}
    {canEdit && deleteOpen && <form onSubmit={remove} className="asset-editor-delete"><h4>자산 삭제 확인</h4><p>분석·점검·SBOM 이력이나 설치·계약 연결이 있는 자산은 삭제할 수 없습니다. 운영에서 제외하려면 모니터링을 해제하세요.</p><p>삭제할 자산번호 <strong>{current.asset_tag}</strong>를 입력하세요. 삭제 후 되돌릴 수 없습니다.</p><label>삭제 확인 자산번호<input autoComplete="off" value={confirmation} disabled={pending} onChange={(e) => setConfirmation(e.target.value)} /></label><div className="asset-editor-heading"><button type="submit" disabled={pending || confirmation !== current.asset_tag}>자산 영구 삭제</button><button type="button" className="secondary" disabled={pending} onClick={() => { setDeleteOpen(false); setConfirmation(''); setError('') }}>삭제 취소</button></div></form>}
    {detailTab === 'timeline' && <section className="asset-timeline" aria-label="자산 타임라인"><h4>자산 타임라인</h4>{timeline.length ? <ol>{timeline.slice(0, 20).map((event, index) => <li key={`${event.type}-${event.at}-${index}`}><strong>{event.title}</strong><small>{event.at ? new Date(event.at).toLocaleString('ko-KR') : '시각 미기록'}</small><span>{event.detail}</span></li>)}</ol> : <p>분석·점검·SBOM·조치 이력이 없습니다.</p>}</section>}
  </section>
}
