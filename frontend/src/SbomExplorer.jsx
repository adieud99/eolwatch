import { useEffect, useRef, useState } from 'react'
import './Workspace.css'

const riskNames = { EXPIRED: '지원 종료', CRITICAL: '180일 이내', WARN: '365일 이내', SAFE: '지원 중', UNKNOWN: '지원 정보 없음' }
const qualityNames = { serial_number: '문서 식별자', timestamp: '생성 시각', authors: '작성자', tools: '생성 도구', component_names: '구성요소 이름', component_versions: '버전', component_suppliers: '공급자', component_unique_ids: '구성요소 식별자', dependency_relationships: '의존관계', license_information: '라이선스', document_namespace: '문서 네임스페이스', creation_info: '생성 정보', package_names: '패키지 이름', package_versions: '패키지 버전' }
const display = (value) => typeof value === 'string' ? value : JSON.stringify(value)
const when = (value) => value ? new Date(value).toLocaleString('ko-KR') : '미기록'

function Pager({ total, offset, size, busy, onChange, label }) {
  return <div className="workspace-pagination"><span>{total}건 · {total ? offset + 1 : 0}–{Math.min(offset + size, total)}건 표시</span><div className="action-row"><button className="table-button" aria-label={`${label} 이전 페이지`} disabled={busy || !offset} onClick={() => onChange(Math.max(0, offset - size))}>이전</button><button className="table-button" aria-label={`${label} 다음 페이지`} disabled={busy || offset + size >= total} onClick={() => onChange(offset + size)}>다음</button></div></div>
}

function ComponentDetail({ component, sbomId, request, canEdit, onUpdated, onSelect, onClose }) {
  const [date, setDate] = useState(component.override_support_end_date || '')
  const [url, setUrl] = useState(component.lifecycle_origin === 'component' ? component.lifecycle_source_url || '' : '')
  const [direction, setDirection] = useState('both')
  const [offset, setOffset] = useState(0)
  const [relations, setRelations] = useState({ items: [], total: 0 })
  const [busy, setBusy] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [relationError, setRelationError] = useState('')
  const [reload, setReload] = useState(0)
  const mutation = useRef(null)
  useEffect(() => () => mutation.current?.abort(), [])
  useEffect(() => {
    const controller = new AbortController(); setBusy(true); setRelationError(''); setRelations({ items: [], total: 0 })
    request(`/sboms/${sbomId}/dependencies?component_id=${component.id}&direction=${direction}&limit=20&offset=${offset}`, { signal: controller.signal })
      .then((value) => { if (!controller.signal.aborted) setRelations(value) })
      .catch((reason) => { if (!controller.signal.aborted) setRelationError(reason.message) })
      .finally(() => { if (!controller.signal.aborted) setBusy(false) })
    return () => controller.abort()
  }, [sbomId, component.id, direction, offset, reload, request])

  async function save(event, inherit = false) {
    event.preventDefault(); if (!canEdit || mutation.current || saving) return
    const controller = new AbortController(); mutation.current = controller; setSaving(true); setError('')
    try {
      const updated = await request(`/sboms/components/${component.id}/lifecycle`, { method: 'PATCH', signal: controller.signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ support_end_date: inherit ? null : date || null, lifecycle_source_url: inherit ? null : url || null }) })
      if (!controller.signal.aborted) { if (inherit) { setDate(''); setUrl('') } onUpdated(updated) }
    } catch (reason) { if (!controller.signal.aborted) setError(reason.message) }
    finally { if (mutation.current === controller) mutation.current = null; if (!controller.signal.aborted) setSaving(false) }
  }
  return <section className="workspace-detail" aria-label="구성요소 상세">
    <div className="workspace-title"><div><h3>{component.name} {component.version}</h3><p>분석 당시 구성요소 · {component.supplier || '공급자 미기록'}</p></div><button className="secondary" disabled={saving} onClick={onClose}>상세 닫기</button></div>
    <dl className="workspace-metadata"><dt>PURL</dt><dd><code>{component.purl || '미기록'}</code></dd><dt>CPE</dt><dd><code>{component.cpe || '미기록'}</code></dd><dt>문서 내 식별자</dt><dd><code>{component.bom_ref}</code></dd><dt>라이선스</dt><dd>{component.licenses?.map(display).join(', ') || '미기록'}</dd><dt>해시</dt><dd>{component.hashes?.length ? component.hashes.map((hash, index) => <code key={index} className="workspace-line">{display(hash)}</code>) : '미기록'}</dd><dt>지원 상태</dt><dd>{riskNames[component.risk_level]} · {component.support_end_date || '날짜 미기록'} · {component.lifecycle_origin === 'component' ? '이 구성요소에 개별 지정' : component.lifecycle_origin === 'product' ? '제품 공통 정보 상속' : '미확인'}</dd><dt>공식 근거</dt><dd>{/^https?:\/\//.test(component.lifecycle_source_url || '') ? <a href={component.lifecycle_source_url} target="_blank" rel="noreferrer">{component.lifecycle_source_url}</a> : '미기록'}</dd></dl>
    {canEdit && <form className="workspace-form" onSubmit={save}><fieldset disabled={saving}><legend>이 구성요소의 지원 정보</legend><label>개별 지원종료일<input type="date" value={date} required onChange={(event) => setDate(event.target.value)} /></label><label>개별 공식 근거 URL<input type="url" required value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://프로젝트의-공식-지원-정책" /></label><p className="workspace-full workspace-help">개별 날짜는 이 SBOM의 구성요소에 적용됩니다. 공통 제품 날짜는 제품·계약 메뉴에서 관리합니다.</p>{error && <p className="form-error" role="alert">{error}</p>}<div className="workspace-full action-row"><button className="primary" disabled={saving || !date || !url}>개별 지원 정보 저장</button><button type="button" className="secondary" disabled={saving || component.lifecycle_origin !== 'component'} onClick={(event) => save(event, true)}>개별 지정 해제 · 제품 정보 상속</button></div></fieldset></form>}
    <div className="workspace-title"><h3>의존·포함 관계</h3><label>관계 방향<select value={direction} onChange={(event) => { setDirection(event.target.value); setOffset(0) }}><option value="both">양쪽 관계</option><option value="outgoing">이 구성요소가 참조</option><option value="incoming">이 구성요소를 참조</option></select></label></div>
    <p className="workspace-help">원본 SBOM의 의존·포함 관계를 정규화한 연결입니다. 관계가 기록되지 않은 경우에도 실제 의존성이 없다고 단정할 수 없습니다.</p>
    {relationError && <p className="form-error" role="alert">{relationError} <button className="table-button" onClick={() => setReload((value) => value + 1)}>관계 다시 조회</button></p>}
    {busy ? <p role="status">관계를 불러오는 중…</p> : <ul className="dependency-list">{relations.items.map((edge) => <li key={edge.id}>{['source', 'target'].map((side, index) => <span key={side}>{index === 1 && <span className="dependency-arrow" aria-label="참조 방향">→</span>}{edge[side].id ? <button className="table-button" disabled={edge[side].id === component.id} onClick={() => onSelect(edge[side].id)}>{edge[side].name} {edge[side].version}</button> : <code>{edge[side].ref} (문서 내 대상 정보 없음)</code>}</span>)}</li>)}{!relations.items.length && !relationError && <li>선택한 방향의 기록된 관계가 없습니다.</li>}</ul>}
    <Pager total={relations.total} offset={offset} size={20} busy={busy} onChange={setOffset} label="관계" />
  </section>
}

export default function SbomExplorer({ sbomId, request, download, canEdit, onChanged, onClose, onViewCve }) {
  const [metadata, setMetadata] = useState(null)
  const [page, setPage] = useState({ items: [], total: 0 })
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [metadataError, setMetadataError] = useState('')
  const [detailError, setDetailError] = useState('')
  const [reload, setReload] = useState(0)
  const [downloading, setDownloading] = useState(false)
  const detailRequest = useRef(null)
  const downloadRequest = useRef(null)
  useEffect(() => () => { detailRequest.current?.abort(); downloadRequest.current?.abort() }, [])
  useEffect(() => {
    const controller = new AbortController(); setMetadataError('')
    request(`/sboms/${sbomId}/detail`, { signal: controller.signal }).then((result) => { if (!controller.signal.aborted) setMetadata(result) }).catch((reason) => { if (!controller.signal.aborted) setMetadataError(reason.message) })
    return () => controller.abort()
  }, [sbomId, request, reload])
  useEffect(() => {
    const controller = new AbortController(); setBusy(true); setError(''); setPage({ items: [], total: 0 })
    request(`/sboms/${sbomId}/component-page?q=${encodeURIComponent(query)}&limit=50&offset=${offset}`, { signal: controller.signal })
      .then((result) => { if (!controller.signal.aborted) setPage(result) })
      .catch((reason) => { if (!controller.signal.aborted) setError(reason.message) })
      .finally(() => { if (!controller.signal.aborted) setBusy(false) })
    return () => controller.abort()
  }, [sbomId, query, offset, request, reload])

  async function choose(id) {
    const controller = new AbortController(); detailRequest.current?.abort(); detailRequest.current = controller; setDetailError('')
    try { const item = await request(`/sboms/${sbomId}/components/${id}`, { signal: controller.signal }); if (!controller.signal.aborted) setSelected(item) }
    catch (reason) { if (!controller.signal.aborted) setDetailError(reason.message) }
  }
  async function raw() {
    if (downloadRequest.current) return
    const controller = new AbortController(); downloadRequest.current = controller; setDownloading(true); setDetailError('')
    try { await download(`/sboms/${sbomId}/raw`, `eolwatch-sbom-${sbomId}.json`, controller.signal) }
    catch (reason) { if (!controller.signal.aborted) setDetailError(reason.message) }
    finally { if (downloadRequest.current === controller) downloadRequest.current = null; if (!controller.signal.aborted) setDownloading(false) }
  }
  return <section className="panel workspace-panel" aria-label="SBOM 상세 탐색">
    <div className="workspace-title"><div><span className="eyebrow">SBOM EXPLORER</span><h2>SBOM #{sbomId} 상세</h2><p>{metadata?.asset ? `${metadata.asset.asset_tag} · ${metadata.asset.name}` : '자산 미연결'} · {metadata?.bom_format} {metadata?.spec_version}</p></div><div className="action-row"><button className="secondary" disabled={downloading} onClick={raw}>{downloading ? '다운로드 중…' : 'SBOM 원본 JSON'}</button><button className="secondary" onClick={() => onViewCve(sbomId)}>이 SBOM의 CVE 보기</button><button className="table-button" onClick={onClose}>상세 탐색 닫기</button></div></div>
    {metadataError && <p className="form-error" role="alert">{metadataError}</p>}
    {metadata && <><dl className="workspace-metadata"><dt>문서 식별자</dt><dd><code>{metadata.serial_number}</code></dd><dt>생성 / 등록</dt><dd>{when(metadata.generated_at)} / {when(metadata.imported_at)}</dd><dt>구성요소 / 관계</dt><dd>{metadata.component_count}개 / {metadata.dependency_count}개</dd><dt>SBOM 품질</dt><dd>{metadata.quality_score}점 · {metadata.quality_details?.profile || '내부 품질 프로파일'}</dd></dl><details className="workspace-quality"><summary>품질 검사 항목과 누락 정보</summary><ul>{Object.entries(metadata.quality_details?.checks || {}).map(([name, passed]) => <li key={name}><strong>{passed ? '충족' : '누락'}</strong> · {qualityNames[name] || name}</li>)}</ul><p className="workspace-help">품질 점수는 기록의 완전성을 점검하며 취약점이 없음을 뜻하지 않습니다.</p></details></>}
    <form className="workspace-search" onSubmit={(event) => { event.preventDefault(); setQuery(search.trim()); setOffset(0); setSelected(null) }}><label>구성요소 검색<input value={search} maxLength={200} onChange={(event) => setSearch(event.target.value)} placeholder="패키지 이름, 버전, PURL, CPE, 공급자" /></label><button className="primary">검색</button></form>
    {error && <p className="form-error" role="alert">{error} <button className="table-button" onClick={() => setReload((value) => value + 1)}>다시 조회</button></p>}
    {detailError && <p className="form-error" role="alert">{detailError}</p>}
    {busy ? <p role="status">구성요소를 불러오는 중…</p> : <div className="table-wrap"><table aria-label="SBOM 구성요소"><thead><tr><th>패키지</th><th>분석 당시 버전</th><th>공급자</th><th>라이선스</th><th>지원 상태</th><th>상세</th></tr></thead><tbody>{page.items.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>{item.purl || item.bom_ref}</small></td><td>{item.version || '미기록'}</td><td>{item.supplier || '미기록'}</td><td>{item.licenses?.map(display).join(', ') || '미기록'}</td><td>{riskNames[item.risk_level]}<small>{item.support_end_date}</small></td><td><button className="table-button" aria-label={`${item.name} ${item.version || ''} 상세 보기`} onClick={() => choose(item.id)}>상세·관계</button></td></tr>)}{!page.items.length && !error && <tr><td colSpan={6} className="empty">검색 조건에 맞는 구성요소가 없습니다.</td></tr>}</tbody></table></div>}
    <Pager total={page.total} offset={offset} size={50} busy={busy} onChange={setOffset} label="구성요소" />
    {selected && <ComponentDetail key={selected.id} component={selected} sbomId={sbomId} request={request} canEdit={canEdit} onClose={() => { detailRequest.current?.abort(); setSelected(null) }} onSelect={choose} onUpdated={(updated) => { setSelected(updated); setPage((current) => ({ ...current, items: current.items.map((item) => item.id === updated.id ? updated : item) })); onChanged('구성요소 지원 정보를 저장했습니다.') }} />}
  </section>
}
