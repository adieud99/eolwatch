import { useEffect, useRef, useState } from 'react'
import './Workspace.css'

const profiles = { 'ubuntu-dpkg-installed': 'OS 설치 패키지' }
export function scopeLabel(scope = '') {
  if (scope.startsWith('source-zip:')) return `소스 ZIP · ${scope.slice('source-zip:'.length)}`
  if (scope.startsWith('source-git:')) return `Git 저장소 · ${scope.slice('source-git:'.length)}`
  return profiles[scope] || scope
}
export function isExecutableScope(scope = '') {
  if (scope.startsWith('source-zip:') || scope.startsWith('source-git:')) return !!scope.slice('source-zip:'.length).trim()
  return Object.hasOwn(profiles, scope)
}

const MANIFEST_ACCEPT = '.zip,application/zip,.txt,.json,.lock,.xml,.toml,.yaml,.yml,.mod,.sum,.kts,.gradle,.csproj,.resolved,Pipfile.lock,Gemfile.lock,Cargo.lock'
const isSourceScope = (scope = '') => scope.startsWith('source-zip:') || scope.startsWith('source-git:')

// Source scan form: a ZIP / dependency file upload or a Git repository, stored under a target + project name.
export default function AnalysisTargets({ assets, canEdit, request, onJobQueued, onAssetCreated, initialAssetId, initialScope, initialProjectName, initialGitUrl, initialGitRef }) {
  const [sourceKind, setSourceKind] = useState('file')
  const [gitUrl, setGitUrl] = useState('')
  const [gitRef, setGitRef] = useState('')
  const [gitToken, setGitToken] = useState('')
  const [assetId, setAssetId] = useState('')
  const [creating, setCreating] = useState(false)       // inline '새 대상' form
  const [newTag, setNewTag] = useState('')
  const [newName, setNewName] = useState('')
  const [created, setCreated] = useState([])            // targets made here, shown until the parent reloads
  const [project, setProject] = useState('')
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const operation = useRef(null)
  const fileInput = useRef(null)

  useEffect(() => {
    operation.current?.abort(); operation.current = null; setBusy(''); setError('')
    setAssetId(initialAssetId == null ? '' : String(initialAssetId))
    setFile(null); if (fileInput.current) fileInput.current.value = ''
    setSourceKind(initialScope?.startsWith('source-git:') ? 'git' : 'file'); setGitUrl(initialGitUrl || ''); setGitRef(initialGitRef || ''); setGitToken('')
    setProject(initialScope && !isExecutableScope(initialScope) ? '' : initialProjectName || (isSourceScope(initialScope) ? initialScope.slice('source-zip:'.length) : ''))
  }, [initialAssetId, initialScope, initialProjectName, initialGitUrl, initialGitRef])
  useEffect(() => () => operation.current?.abort(), [])

  async function createTarget() {
    if (busy) return
    const controller = new AbortController(); operation.current?.abort(); operation.current = controller; setBusy('target'); setError('')
    try {
      const asset = await request('/assets', { method: 'POST', signal: controller.signal, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ asset_tag: newTag.trim(), name: newName.trim(), asset_type: 'server', monitored: false }) })
      if (controller.signal.aborted) return
      setCreated((current) => [...current, asset]); setAssetId(String(asset.id)); setCreating(false); setNewTag(''); setNewName('')
      setMessage(`대상 ${asset.asset_tag}을(를) 만들었습니다.`); onAssetCreated?.(asset)
    } catch (reason) { if (!controller.signal.aborted) setError(reason.message) }
    finally { if (operation.current === controller) { operation.current = null; setBusy('') } }
  }

  async function submit(event) {
    event.preventDefault()
    if (!canEdit || operation.current || !assetId) return
    const form = event.currentTarget
    if (!form?.reportValidity()) return
    if (sourceKind === 'git') {
      if (!project.trim() || !/^https:\/\/[^\s@]+$/.test(gitUrl.trim())) { setError('저장소 주소는 계정 정보가 없는 https:// 주소여야 합니다.'); return }
    } else if (!file || !project.trim()) return
    const controller = new AbortController(); operation.current = controller; setBusy('analysis'); setError(''); setMessage('')
    try {
      if (sourceKind === 'git') {
        const body = { repository_url: gitUrl.trim(), project_name: project.trim(), ...(gitRef.trim() ? { ref: gitRef.trim() } : {}), ...(gitToken ? { access_token: gitToken } : {}) }
        const job = await request(`/analyses/assets/${assetId}/git`, { method: 'POST', signal: controller.signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
        if (!controller.signal.aborted) { setGitToken(''); onJobQueued(job) }
      } else {
        if (file.size > 500 * 1024 * 1024) throw new Error('ZIP 파일은 500 MiB까지 업로드할 수 있습니다.')
        const data = new FormData(); data.append('file', file); data.append('project_name', project.trim())
        const job = await request(`/analyses/assets/${assetId}/uploads`, { method: 'POST', body: data, signal: controller.signal })
        if (!controller.signal.aborted) { setFile(null); if (fileInput.current) fileInput.current.value = ''; onJobQueued(job) }
      }
    } catch (reason) { if (!controller.signal.aborted) setError(reason.message) }
    finally { if (operation.current === controller) operation.current = null; if (!controller.signal.aborted) setBusy('') }
  }

  const targets = [...assets, ...created.filter((item) => !assets.some((known) => known.id === item.id))]
  return (
    <section className="panel workspace-panel" aria-label="프로젝트 분석">
      <span className="eyebrow">SOURCE SCAN</span><h2>소스 검사</h2><p className="workspace-help">소스 ZIP이나 의존성 파일을 올리거나 Git 저장소 주소를 입력하면 의존성 목록을 뽑아 알려진 취약점과 대조합니다. 결과는 아래에서 고른 대상 아래에 프로젝트 이름으로 쌓입니다.</p>
      {initialScope && !isExecutableScope(initialScope) && <p className="workspace-help">이전 검사의 입력 정보가 없어 새 ZIP 입력으로 시작합니다.</p>}
      {canEdit ? <>
        <div className="analysis-input-tabs" role="group" aria-label="소스 입력 방식"><button type="button" className="secondary" disabled={!!busy} aria-pressed={sourceKind === 'file'} onClick={() => { setSourceKind('file'); setError('') }}>소스 ZIP · 의존성 파일</button><button type="button" className="secondary" disabled={!!busy} aria-pressed={sourceKind === 'git'} onClick={() => { setSourceKind('git'); setError('') }}>Git 저장소</button></div>
        <form className="workspace-form" onSubmit={submit}><fieldset disabled={!!busy}><legend>{sourceKind === 'git' ? '검사할 Git 저장소' : '검사할 프로젝트'}</legend>
          <label>결과를 저장할 대상<select required value={assetId} onChange={(event) => setAssetId(event.target.value)}><option value="">대상 선택</option>{targets.map((item) => <option key={item.id} value={item.id}>{item.asset_tag} · {item.name}</option>)}</select>{!creating && <button type="button" className="table-button" onClick={() => { setCreating(true); setError('') }}>+ 새 대상</button>}</label>
          <label>프로젝트 이름<input required maxLength={80} value={project} onChange={(event) => setProject(event.target.value)} placeholder="예: 주문 API" /></label>
          {creating && <fieldset className="new-target"><legend>새 대상 (검사 결과를 모아 둘 이름)</legend>
            <label>대상 번호<input value={newTag} maxLength={64} placeholder="예: PROJ-ORDERS" onChange={(event) => setNewTag(event.target.value)} /></label>
            <label>대상 이름<input value={newName} maxLength={120} placeholder="예: 주문 서비스" onChange={(event) => setNewName(event.target.value)} /></label>
            <div className="action-row"><button type="button" className="primary" disabled={!newTag.trim() || !newName.trim() || busy === 'target'} onClick={createTarget}>대상 만들기</button><button type="button" className="secondary" onClick={() => { setCreating(false); setNewTag(''); setNewName('') }}>취소</button></div>
            <small className="subtle">서버 주소 없이 결과만 쌓는 대상입니다. 서버는 인프라 검사에서 등록하세요.</small>
          </fieldset>}
          {sourceKind === 'git'
            ? <><label className="workspace-full">저장소 주소 (https)<input required maxLength={500} value={gitUrl} onChange={(event) => setGitUrl(event.target.value)} placeholder="https://github.com/org/repo" /></label><label>브랜치 또는 태그<input maxLength={200} value={gitRef} onChange={(event) => setGitRef(event.target.value)} placeholder="비우면 기본 브랜치" /></label><label>접근 토큰 (비공개 저장소)<input type="password" maxLength={400} autoComplete="off" value={gitToken} onChange={(event) => setGitToken(event.target.value)} placeholder="공개 저장소는 비움" /></label><p className="workspace-help workspace-full">읽기 전용으로 최신 커밋만 얕게 복제해 의존성 파일을 읽습니다. 코드를 빌드하거나 실행하지 않습니다. 토큰은 복제에 한 번 쓰고 저장하지 않습니다. 같은 프로젝트 이름으로 다시 검사하면 전후 비교할 수 있습니다.</p></>
            : <><label className="workspace-full">소스 ZIP 또는 의존성 파일<input ref={fileInput} type="file" required accept={MANIFEST_ACCEPT} onChange={(event) => setFile(event.target.files?.[0] || null)} /></label><p className="workspace-help workspace-full">최대 500 MiB. 잠금 파일과 패키지 명세가 포함된 소스 ZIP, 또는 requirements.txt·package-lock.json·pom.xml·go.sum 같은 의존성 파일 하나를 선택하세요. 같은 대상·프로젝트 이름으로 다음 버전을 올리면 전후 비교할 수 있습니다. 패키지를 설치하거나 프로그램을 실행하지 않으며, 포함된 메타데이터에서 구성요소를 식별합니다.</p></>}
          {error && <p className="form-error workspace-full" role="alert">{error}</p>}
          <div className="action-row workspace-full"><button className="primary" disabled={!!busy || !assetId}>{busy === 'analysis' ? '검사 요청 중…' : '검사 시작'}</button></div>
        </fieldset></form>
      </> : <p className="workspace-help">조회 계정은 결과만 볼 수 있습니다. 검사 실행은 관리자만 할 수 있습니다.</p>}
      {message && <p className="inline-result" role="status">{message}</p>}
    </section>
  )
}
