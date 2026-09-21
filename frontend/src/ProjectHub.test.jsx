import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ProjectHub from './ProjectHub'

const assets = [{ id: 1, asset_tag: 'APP-1', name: '주문 서버' }, { id: 2, asset_tag: 'APP-2', name: '결제 서버' }]
const run = (id, changes = {}) => ({ id, asset_id: 1, asset_tag: 'APP-1', asset_name: '주문 서버', scan_scope: 'source-zip:orders', sbom_id: id + 1000, imported_at: new Date(Date.UTC(2026, 0, 1, 0, id)).toISOString(), scanner: 'Grype', scanner_version: '0.104', cve_count: 0, component_count: 4, ...changes })
const job = { id: 70, asset_id: 1, asset_tag: 'APP-1', scan_scope: 'source-zip:orders', status: 'FAILED', requested_at: '2026-09-16T00:00:00Z', error_message: '검증용 작업 오류', error_code: 'SCAN_FAILED' }
const group = { asset_id: 1, asset_tag: 'APP-1', asset_name: '주문 서버', scan_scope: 'source-zip:orders', project_name: 'orders', analysis_count: 205, job_count: 206, upload_count: 1, latest_analysis: run(205), latest_job: job, schedule: null }
const osGroup = { ...group, scan_scope: 'ubuntu-dpkg-installed', project_name: null, analysis_count: 1, latest_analysis: run(300, { scan_scope: 'ubuntu-dpkg-installed', cve_count: 40 }), upload_count: 0 }
const upload = { id: 'upload-1', asset_id: 1, project_name: 'orders', filename: 'orders-v1.zip', sha256: 'a'.repeat(64), size_bytes: 2048, created_at: '2026-09-15T00:00:00Z', job_count: 1, latest_job: { ...job, status: 'SUCCESS', sbom_id: 1205 }, storage_status: 'AVAILABLE', content_verified: false }
const page = (items, total = items.length, offset = 0) => ({ items, total, limit: 20, offset })
function route(path) {
  if (path.startsWith('/analyses/projects?')) return page([group, osGroup])
  if (path.startsWith('/analyses/history?')) return page([run(205), run(204)], 205)
  if (path.startsWith('/analyses/job-history?')) return page([job])
  if (path.startsWith('/analyses/uploads?')) return page([upload])
  if (path === '/analyses/storage') return { files: 2, bytes: 2048, free_disk_bytes: 1024 ** 3, referenced_files: 1, unreferenced_files: 1, missing_files: 0, size_mismatch_files: 0, unsafe_files: 0, temp_files: 0, content_verified: false, checked_at: '2026-09-16T00:00:00Z' }
  throw new Error(`Unexpected request ${path}`)
}
function open(overrides = {}) {
  const props = { assets, canEdit: true, request: vi.fn(async (path) => route(path)), download: vi.fn(async () => {}), onChanged: vi.fn(), onJobQueued: vi.fn(), onViewResult: vi.fn(), onViewSbom: vi.fn(), onCompare: vi.fn(), onNewAnalysis: vi.fn(), onSelectionChange: vi.fn(), onViewWork: vi.fn(), ...overrides }
  return { ...render(<ProjectHub {...props} />), props }
}
async function selectZip() { fireEvent.click(await screen.findByRole('button', { name: 'APP-1 소스 ZIP · orders 이력 보기' })); await screen.findByText('검사 #204') }
const resultRow = (id) => screen.getByText(`검사 #${id}`, { selector: 'strong' }).closest('tr')
afterEach(() => { cleanup(); vi.useRealTimers() })

describe('프로젝트별 서버 페이지 이력', () => {
  it('205개 분석 중 마지막 페이지를 직접 조회하고 오래된 결과·SBOM·원본 및 전후 비교로 이동한다', async () => {
    const request = vi.fn(async (path) => path.startsWith('/analyses/history?') ? new URLSearchParams(path.split('?')[1]).get('offset') === '200' ? page([run(5), run(4), run(3), run(2), run(1)], 205, 200) : page([run(205)], 205) : route(path))
    const view = open({ request })
    fireEvent.click(await screen.findByRole('button', { name: 'APP-1 소스 ZIP · orders 이력 보기' }))
    await waitFor(() => expect(resultRow(205)).toBeInTheDocument())
    fireEvent.click(within(resultRow(205)).getByRole('button', { name: '이후로' }))
    fireEvent.change(screen.getByLabelText('검사 이동할 쪽'), { target: { value: '11' } })
    fireEvent.click(screen.getByRole('button', { name: '검사 이동' }))
    await waitFor(() => expect(resultRow(1)).toBeInTheDocument())
    expect(request.mock.calls.filter(([path]) => path.startsWith('/analyses/history?'))).toHaveLength(2)
    expect(request.mock.calls.find(([path]) => path.includes('offset=200'))[0]).toContain('limit=20')
    expect(screen.getByText('총 205건 · 11 / 11쪽')).toBeInTheDocument()
    fireEvent.click(within(resultRow(1)).getByRole('button', { name: '이전으로' }))
    await act(async () => fireEvent.click(screen.getByRole('button', { name: '선택한 두 검사 비교' })))
    expect(view.props.onCompare).toHaveBeenCalledWith(1, 205, expect.any(AbortSignal))
    fireEvent.click(within(resultRow(1)).getByRole('button', { name: 'CVE 결과' }))
    fireEvent.click(within(resultRow(1)).getByRole('button', { name: '의존성 목록' }))
    expect(view.props.onViewResult).toHaveBeenCalledWith(1001)
    expect(view.props.onViewSbom).toHaveBeenCalledWith(1001)
    await act(async () => fireEvent.click(within(resultRow(1)).getByRole('button', { name: '원본 파일' })))
    expect(view.props.download).toHaveBeenCalledWith('/analyses/1/bundle', 'eolwatch-analysis-1.json', expect.any(AbortSignal))
  })

  it('검색과 날짜·상태를 서버 쿼리로 전달하고 잘못된 기간은 요청하지 않는다', async () => {
    const { props } = open()
    await selectZip()
    fireEvent.click(screen.getByRole('tab', { name: '작업 이력' }))
    await screen.findByText('작업 #70', { selector: 'strong' })
    fireEvent.change(screen.getByLabelText('조회 시작일'), { target: { value: '2026-09-15' } })
    fireEvent.change(screen.getByLabelText('조회 종료일'), { target: { value: '2026-09-16' } })
    fireEvent.change(screen.getByLabelText('작업 상태'), { target: { value: 'FAILED' } })
    fireEvent.change(screen.getByLabelText('이력 검색'), { target: { value: 'orders' } })
    fireEvent.click(screen.getByRole('button', { name: '조회' }))
    await waitFor(() => expect(props.request.mock.calls.some(([path]) => path.includes('date_from=2026-09-15'))).toBe(true))
    const params = new URLSearchParams(props.request.mock.calls.filter(([path]) => path.startsWith('/analyses/job-history?')).at(-1)[0].split('?')[1])
    expect(Object.fromEntries(params)).toEqual({ asset_id: '1', scan_scope: 'source-zip:orders', q: 'orders', date_from: '2026-09-15', date_to: '2026-09-16', status: 'FAILED', limit: '20', offset: '0' })
    const count = props.request.mock.calls.length
    fireEvent.change(screen.getByLabelText('조회 종료일'), { target: { value: '2026-09-14' } })
    fireEvent.click(screen.getByRole('button', { name: '조회' }))
    expect(screen.getByText('조회 시작일은 종료일보다 늦을 수 없습니다.')).toBeInTheDocument()
    expect(props.request).toHaveBeenCalledTimes(count)
    fireEvent.change(screen.getByLabelText('대상'), { target: { value: '2' } })
    fireEvent.change(screen.getByLabelText('프로젝트 검색'), { target: { value: '결제' } })
    fireEvent.click(screen.getByRole('button', { name: '프로젝트 조회' }))
    await waitFor(() => expect(props.request.mock.calls.some(([path]) => path.startsWith('/analyses/projects?asset_id=2&q='))).toBe(true))
    expect(screen.queryByRole('region', { name: '선택한 프로젝트' })).not.toBeInTheDocument()
  })

  it('미래 작업 실패와 0 CVE 성공 분석을 구분하고 다른 범위 선택 시 비교를 초기화한다', async () => {
    const { props } = open()
    await selectZip()
    const detail = screen.getByRole('region', { name: '선택한 프로젝트' })
    expect(within(detail).getByText('검사 #205 · CVE 0건')).toBeInTheDocument()
    expect(within(detail).getByText('#70 · 실패')).toBeInTheDocument()
    fireEvent.click(within(resultRow(205)).getByRole('button', { name: '이전으로' }))
    fireEvent.click(within(resultRow(204)).getByRole('button', { name: '이후로' }))
    expect(screen.getByRole('button', { name: '선택한 두 검사 비교' })).toBeDisabled()
    expect(screen.getByText(/시간 순서에 맞는 두 검사/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'APP-1 OS 설치 패키지 이력 보기' }))
    await screen.findByRole('heading', { name: 'APP-1 · OS 설치 패키지' })
    expect(screen.getByText('이전: 선택 안 함 · 이후: 선택 안 함')).toBeInTheDocument()
    expect(props.onSelectionChange).toHaveBeenLastCalledWith({ assetId: 1, scanScope: 'ubuntu-dpkg-installed' })
  })

  it('ZIP 원본 식별정보를 보여주고 다운로드 실패 후 재시도·중복 없는 재검사을 지원한다', async () => {
    let complete
    const request = vi.fn((path, options) => options?.method === 'POST' ? new Promise((resolve) => { complete = resolve }) : Promise.resolve(route(path)))
    const download = vi.fn().mockRejectedValueOnce(new Error('원본 SHA-256이 일치하지 않습니다.')).mockResolvedValueOnce(undefined)
    const { props } = open({ request, download })
    await selectZip(); fireEvent.click(screen.getByRole('tab', { name: '저장된 ZIP' }))
    await screen.findByText(upload.sha256)
    fireEvent.click(screen.getByRole('button', { name: 'ZIP 다운로드' }))
    await screen.findByText('원본 SHA-256이 일치하지 않습니다.')
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'ZIP 다운로드' })))
    expect(download).toHaveBeenLastCalledWith('/analyses/uploads/upload-1/raw', 'orders-v1.zip', expect.any(AbortSignal))
    const replay = screen.getByRole('button', { name: '이 ZIP 다시 검사' })
    fireEvent.click(replay); fireEvent.click(replay)
    const posts = request.mock.calls.filter(([, options]) => options?.method === 'POST')
    expect(posts).toHaveLength(1); expect(posts[0][0]).toBe('/analyses/uploads/upload-1/jobs')
    expect(posts[0][1].body).toBeUndefined()
    await act(async () => complete({ ...job, id: 71, status: 'QUEUED' }))
    expect(props.onJobQueued).toHaveBeenCalledWith(expect.objectContaining({ id: 71, status: 'QUEUED' }))
  })

  it('보관 파일이 없으면 다운로드·재검사을 막고 조회자는 모든 편집 기능이 없다', async () => {
    const request = vi.fn(async (path) => path.startsWith('/analyses/uploads?') ? page([{ ...upload, storage_status: 'MISSING' }]) : route(path))
    const view = open({ request })
    await selectZip(); fireEvent.click(screen.getByRole('tab', { name: '저장된 ZIP' }))
    await screen.findByText(/파일 없음/)
    expect(screen.getByRole('button', { name: 'ZIP 다운로드' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '이 ZIP 다시 검사' })).toBeDisabled()
    view.unmount()
    open({ canEdit: false })
    await selectZip(); fireEvent.click(screen.getByRole('tab', { name: '저장된 ZIP' }))
    await screen.findByText('재검사는 관리자만')
    expect(screen.getByRole('button', { name: 'ZIP 다운로드' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: /새.*분석|ZIP 재검사|보관 현황/ })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: '작업 이력' }))
    await screen.findByText('작업 #70', { selector: 'strong' })
    expect(screen.queryByRole('button', { name: '검사 취소' })).not.toBeInTheDocument()
  })

  it('취소 요청은 한 번만 보내고 취소 처리 중 상태가 끝날 때까지 중복 취소를 막는다', async () => {
    let complete
    let status = 'SCANNING'
    const request = vi.fn((path, options) => options?.method === 'POST' ? new Promise((resolve) => { complete = resolve }) : Promise.resolve(path.startsWith('/analyses/job-history?') ? page([{ ...job, status, error_message: null }]) : route(path)))
    open({ request }); await selectZip(); fireEvent.click(screen.getByRole('tab', { name: '작업 이력' }))
    const cancel = await screen.findByRole('button', { name: '검사 취소' })
    fireEvent.click(cancel); fireEvent.click(cancel)
    expect(request.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
    expect(request).toHaveBeenCalledWith('/analyses/jobs/70/cancel', expect.objectContaining({ method: 'POST' }))
    status = 'CANCEL_REQUESTED'
    await act(async () => complete({ ...job, status }))
    expect(await screen.findByRole('button', { name: '취소 처리 중' })).toBeDisabled()
  })

  it('최근 목록 밖의 실패 작업을 원래 입력으로 재시도하고 오류 후에도 다시 요청할 수 있다', async () => {
    let attempts = 0
    const request = vi.fn(async (path, options) => { if (options?.method === 'POST') { if (++attempts === 1) throw new Error('다른 검사가 실행 중입니다.'); return { ...job, id: 207, status: 'QUEUED', retry_of_id: 70 } } return route(path) })
    const { props } = open({ request }); await selectZip(); fireEvent.click(screen.getByRole('tab', { name: '작업 이력' }))
    fireEvent.click(await screen.findByRole('button', { name: '다시 검사' }))
    await screen.findByText('다른 검사가 실행 중입니다.')
    await act(async () => fireEvent.click(screen.getByRole('button', { name: '다시 검사' })))
    const posts = request.mock.calls.filter(([, options]) => options?.method === 'POST')
    expect(posts).toHaveLength(2)
    expect(posts[1][0]).toBe('/analyses/jobs/70/retry'); expect(posts[1][1].body).toBeUndefined()
    expect(props.onJobQueued).toHaveBeenCalledWith(expect.objectContaining({ id: 207, retry_of_id: 70 }))
  })

  it('첫 프로젝트 페이지 밖의 범위도 정확한 메타데이터를 읽고 문맥 저장 후 상세를 유지한다', async () => {
    const request = vi.fn(async (path) => path.startsWith('/analyses/projects?') ? new URLSearchParams(path.split('?')[1]).has('scan_scope') ? page([group]) : page([osGroup]) : route(path))
    const view = open({ request, initialAssetId: 1, initialScope: 'source-zip:orders' })
    await screen.findByText('검사 #204')
    expect(within(screen.getByRole('region', { name: '선택한 프로젝트' })).getByText('검사 #205 · CVE 0건')).toBeInTheDocument()
    expect(request).toHaveBeenCalledWith('/analyses/projects?asset_id=1&scan_scope=source-zip%3Aorders&limit=20&offset=0', expect.any(Object))
    fireEvent.click(within(resultRow(204)).getByRole('button', { name: '이전으로' }))
    view.rerender(<ProjectHub {...view.props} initialAssetId={1} initialScope="source-zip:orders" />)
    expect(screen.getByText('이전: 검사 #204 · 이후: 선택 안 함')).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: '선택한 프로젝트' })).getByText('검사 #205 · CVE 0건')).toBeInTheDocument()
  })

  it('프로젝트 전환으로 이전 읽기·다운로드를 중단하고 늦은 응답을 버린다', async () => {
    let completeRead, completeDownload
    const request = vi.fn((path) => path.startsWith('/analyses/history?') && new URLSearchParams(path.split('?')[1]).get('scan_scope') === 'source-zip:orders' ? new Promise((resolve) => { completeRead = resolve }) : Promise.resolve(path.startsWith('/analyses/history?') ? page([run(300, { scan_scope: 'ubuntu-dpkg-installed' })]) : route(path)))
    const download = vi.fn(() => new Promise((resolve) => { completeDownload = resolve }))
    const view = open({ request, download })
    fireEvent.click(await screen.findByRole('button', { name: 'APP-1 소스 ZIP · orders 이력 보기' }))
    const signal = request.mock.calls.find(([path]) => path.startsWith('/analyses/history?'))[1].signal
    fireEvent.click(screen.getByRole('button', { name: 'APP-1 OS 설치 패키지 이력 보기' }))
    await waitFor(() => expect(resultRow(300)).toBeInTheDocument())
    expect(signal.aborted).toBe(true)
    await act(async () => completeRead(page([run(204)])))
    expect(screen.queryByText('검사 #204')).not.toBeInTheDocument()
    fireEvent.click(within(resultRow(300)).getByRole('button', { name: '원본 파일' }))
    const downloadSignal = download.mock.calls[0][2]
    view.unmount(); expect(downloadSignal.aborted).toBe(true)
    await act(async () => completeDownload())
  })

  it('조회 실패를 빈 상태와 구분하고 재시도하며 저장 상태는 관리자 요청 시에만 조회한다', async () => {
    let attempts = 0
    const request = vi.fn(async (path) => { if (path.startsWith('/analyses/projects?') && ++attempts === 1) throw new Error('목록 연결 실패'); return route(path) })
    open({ request })
    await screen.findByText('프로젝트 목록 조회 실패: 목록 연결 실패')
    expect(screen.queryByText(/조건에 맞는 프로젝트가 없습니다/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '다시 불러오기' }))
    await screen.findByRole('button', { name: 'APP-1 소스 ZIP · orders 이력 보기' })
    expect(request.mock.calls.some(([path]) => path === '/analyses/storage')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: '보관 현황 조회' }))
    await screen.findByText(/전체 파일 내용 검증은 수행하지 않았습니다/)
    expect(screen.getByText('접근 불가')).toBeInTheDocument()
  })

  it('다른 탭에서 받은 프로젝트 범위를 열고 새 분석 입력에 동일 대상·이름을 보낸다', async () => {
    const { props } = open({ initialAssetId: 1, initialScope: 'source-zip:orders' })
    await screen.findByText('검사 #204')
    fireEvent.click(screen.getByRole('button', { name: '이 프로젝트 다시 검사' }))
    expect(props.onNewAnalysis).toHaveBeenCalledWith({ assetId: 1, scanScope: 'source-zip:orders', projectName: 'orders', targetPath: '', gitUrl: '', gitRef: '' })
    fireEvent.click(screen.getByRole('button', { name: '이 대상의 조치 목록' }))
    expect(props.onViewWork).toHaveBeenCalledWith(1)
    expect(props.request.mock.calls.some(([path]) => path.startsWith('/analyses/projects?asset_id=1&'))).toBe(true)
  })

  it('수동 가져오기 범위의 이력은 읽을 수 있지만 기록되지 않은 입력으로 재실행하지 않는다', async () => {
    const manual = { ...group, scan_scope: 'uploaded SPDX SBOM', project_name: null }
    open({ initialAssetId: 1, initialScope: manual.scan_scope, request: vi.fn(async (path) => path.startsWith('/analyses/projects?') ? page([manual]) : page([run(1, { scan_scope: manual.scan_scope })])) })
    await screen.findByText('검사 #1', { selector: 'strong' })
    expect(screen.queryByRole('button', { name: '이 프로젝트 다시 검사' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '새 검사' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'CVE 결과' })).toBeEnabled()
  })

  it('실행 중 작업은 요청 종료 후 3초 간격으로 조회하고 언마운트하면 다음 조회를 취소한다', async () => {
    const request = vi.fn(async (path) => path.startsWith('/analyses/job-history?') ? page([{ ...job, status: 'SCANNING' }]) : route(path))
    const view = open({ request }); await selectZip()
    vi.useFakeTimers()
    await act(async () => fireEvent.click(screen.getByRole('tab', { name: '작업 이력' })))
    expect(request.mock.calls.filter(([path]) => path.startsWith('/analyses/job-history?'))).toHaveLength(1)
    await act(async () => vi.advanceTimersByTimeAsync(3000))
    expect(request.mock.calls.filter(([path]) => path.startsWith('/analyses/job-history?'))).toHaveLength(2)
    view.unmount()
    await act(async () => vi.advanceTimersByTimeAsync(6000))
    expect(request.mock.calls.filter(([path]) => path.startsWith('/analyses/job-history?'))).toHaveLength(2)
    expect(request.mock.calls.find(([path]) => path.startsWith('/analyses/job-history?'))[1].signal.aborted).toBe(true)
  })
})

describe('대상 삭제', () => {
  it('프로젝트 상세에서 대상 번호를 확인한 뒤 이력 포함 삭제를 요청하고 목록을 비운다', async () => {
    const project = { asset_id: 7, asset_tag: 'GH-old', asset_name: 'GitHub old', scan_scope: 'source-git:old', project_name: 'old', latest_analysis: null, latest_job: null, schedule: null, analysis_count: 0, job_count: 1, upload_count: 0 }
    let deleted = false
    const request = vi.fn(async (path, options) => {
      if (options?.method === 'DELETE') { deleted = true; return null }
      if (path.startsWith('/analyses/projects?')) return { items: deleted ? [] : [project], total: deleted ? 0 : 1, limit: 20, offset: 0 }
      return { items: [], total: 0, limit: 20, offset: 0 }
    })
    const onChanged = vi.fn(); const onTargetDeleted = vi.fn()
    render(<ProjectHub assets={[{ id: 7, asset_tag: 'GH-old', name: 'GitHub old' }]} canEdit request={request} download={vi.fn()} onChanged={onChanged} onJobQueued={vi.fn()} onViewResult={vi.fn()} onViewSbom={vi.fn()} onCompare={vi.fn()} onNewAnalysis={vi.fn()} onTargetDeleted={onTargetDeleted} />)
    fireEvent.click(await screen.findByRole('button', { name: 'GH-old Git 저장소 · old 이력 보기' }))
    fireEvent.click(await screen.findByRole('button', { name: '대상 삭제…' }))
    const confirm = screen.getByRole('button', { name: '대상 영구 삭제' })
    expect(confirm).toBeDisabled()
    fireEvent.change(screen.getByLabelText('삭제 확인 대상 번호'), { target: { value: 'GH-old' } })
    fireEvent.click(confirm)
    await waitFor(() => expect(onTargetDeleted).toHaveBeenCalledWith(7))
    const [path] = request.mock.calls.find(([, options]) => options?.method === 'DELETE')
    expect(path).toBe('/assets/7?purge=true')
    expect(onChanged).toHaveBeenCalledWith('대상과 이력을 삭제했습니다.')
    await waitFor(() => expect(screen.queryByRole('region', { name: '선택한 프로젝트' })).not.toBeInTheDocument())
  })
})
