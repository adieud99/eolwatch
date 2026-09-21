import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import AnalysisTargets from './AnalysisTargets'

afterEach(cleanup)
const assets = [{ id: 1, asset_tag: 'APP-1', name: '검사 서버', monitored: true, ip_address: '10.0.0.1', ssh_username: 'operator' }, { id: 2, asset_tag: 'UPLOAD-2', name: '업로드 전용', monitored: false }]
const schedule = { id: 9, asset_id: 1, asset_tag: 'APP-1', asset_name: '검사 서버', scan_scope: 'ssh-project-directory:/opt/orders', interval_minutes: 60, enabled: true, next_run_at: '2026-09-16T01:00:00Z' }
function open(overrides = {}) {
  const props = { assets, canEdit: true, request: vi.fn(async () => []), onJobQueued: vi.fn(), ...overrides }
  return { ...render(<AnalysisTargets {...props} />), props }
}

describe('실제 프로젝트 분석 입력', () => {
  it('수동 가져오기의 임의 범위는 잘못된 실행 프로파일로 보내지 않고 새 ZIP 입력으로 연다', async () => {
    const { props } = open({ initialAssetId: 2, initialScope: 'uploaded SPDX SBOM', initialProjectName: '실행 불명', initialTargetPath: '/unknown' })
    expect(screen.getByRole('combobox', { name: /^(결과를 저장할 대상|검사할 서버)/ })).toHaveValue('2')
    expect(screen.getByLabelText('프로젝트 이름')).toHaveValue('')
    expect(screen.queryByLabelText('검사 방식')).not.toBeInTheDocument()
    expect(screen.getByText(/이전 검사의 입력 정보가 없어 새 ZIP 입력/)).toBeInTheDocument()
    await waitFor(() => expect(props.request).toHaveBeenCalledWith('/analyses/schedules', expect.any(Object)))
    expect(props.request.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false)
  })
  it('프로젝트에서 넘어온 ZIP 이름과 서버 범위·경로를 입력에 이어받는다', async () => {
    const view = open({ initialAssetId: 2, initialScope: 'source-zip:orders', initialProjectName: 'orders' })
    expect(screen.getByRole('combobox', { name: /^(결과를 저장할 대상|검사할 서버)/ })).toHaveValue('2')
    expect(screen.getByLabelText('프로젝트 이름')).toHaveValue('orders')
    view.rerender(<AnalysisTargets {...view.props} initialAssetId={1} initialScope="ssh-python-environment:/opt/orders/.venv" initialProjectName="" initialTargetPath="/opt/orders/.venv" />)
    expect(screen.getByRole('combobox', { name: /^(결과를 저장할 대상|검사할 서버)/ })).toHaveValue('1')
    expect(screen.getByLabelText('검사 방식')).toHaveValue('ssh-python-environment')
    expect(screen.getByLabelText('서버 앱 절대 경로')).toHaveValue('/opt/orders/.venv')
    await waitFor(() => expect(view.props.request).toHaveBeenCalledWith('/analyses/schedules', expect.any(Object)))
  })
  it('SSH 설정 없는 대상에도 ZIP과 프로젝트 이름으로 분석 요청을 보낸다', async () => {
    const job = { id: 55, asset_id: 2, status: 'QUEUED', scan_scope: 'source-zip:orders' }
    let resolve
    const request = vi.fn((path, options) => options?.method === 'POST' ? new Promise((done) => { resolve = done }) : Promise.resolve([]))
    const { props } = open({ request })
    fireEvent.change(screen.getByRole('combobox', { name: /^(결과를 저장할 대상|검사할 서버)/ }), { target: { value: '2' } })
    fireEvent.change(screen.getByLabelText('프로젝트 이름'), { target: { value: 'orders' } })
    const file = new File(['zip bytes'], 'orders.zip', { type: 'application/zip' })
    fireEvent.change(screen.getByLabelText('소스 ZIP 또는 의존성 파일'), { target: { files: [file] } })
    // jsdom does not assign a file input's value, so simulate valid browser form validation.
    const form = screen.getByLabelText('프로젝트 이름').closest('form')
    vi.spyOn(form, 'reportValidity').mockReturnValue(true)
    fireEvent.submit(form); fireEvent.submit(form)
    const posts = request.mock.calls.filter(([, options]) => options?.method === 'POST')
    expect(posts).toHaveLength(1)
    expect(posts[0][0]).toBe('/analyses/assets/2/uploads')
    expect(posts[0][1].body.get('project_name')).toBe('orders')
    expect(posts[0][1].body.get('file').name).toBe('orders.zip')
    expect(posts[0][1].headers).toBeUndefined()
    await act(async () => resolve(job))
    expect(props.onJobQueued).toHaveBeenCalledWith(job)
  })

  it('서버의 실제 프로젝트 경로를 보내고 정기 예약을 별도로 등록한다', async () => {
    const request = vi.fn(async (path, options) => options?.method === 'POST' ? schedule : [schedule])
    open({ request })
    fireEvent.click(screen.getByRole('button', { name: '서버 앱 경로' }))
    fireEvent.change(screen.getByRole('combobox', { name: /^(결과를 저장할 대상|검사할 서버)/ }), { target: { value: '1' } })
    fireEvent.change(screen.getByLabelText('서버 앱 절대 경로'), { target: { value: '/opt/orders' } })
    fireEvent.change(screen.getByLabelText('정기 검사 주기 (분)'), { target: { value: '60' } })
    fireEvent.click(screen.getByRole('button', { name: '정기 검사 등록' }))
    await screen.findByText(/정기 검사를 등록했습니다/)
    const post = request.mock.calls.find(([, options]) => options?.method === 'POST')
    expect(post[0]).toBe('/analyses/schedules')
    expect(JSON.parse(post[1].body)).toEqual({ asset_id: 1, scan_scope: 'ssh-project-directory', target_path: '/opt/orders', interval_minutes: 60, enabled: true })
  })

  it('예약 주기와 일시 중지를 저장하고 조회자는 수정할 수 없다', async () => {
    const request = vi.fn(async (path, options) => options?.method === 'PATCH' ? { ...schedule, interval_minutes: 120, enabled: false } : [schedule])
    const view = open({ request })
    await screen.findByLabelText('예약 9 주기')
    fireEvent.change(screen.getByLabelText('예약 9 주기'), { target: { value: '120' } })
    fireEvent.click(screen.getByRole('button', { name: '일시 중지' }))
    await screen.findByRole('button', { name: '다시 실행' })
    const patch = request.mock.calls.find(([, options]) => options?.method === 'PATCH')
    expect(JSON.parse(patch[1].body)).toEqual({ interval_minutes: 120, enabled: false })
    view.unmount(); open({ request, canEdit: false })
    await screen.findByText('실행 중')
    expect(screen.queryByRole('button', { name: '검사 시작' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '일시 중지' })).not.toBeInTheDocument()
  })

  it('예약을 삭제하면 목록에서 사라진다', async () => {
    const request = vi.fn(async (path, options) => options?.method === 'DELETE' ? null : [schedule])
    open({ request })
    await screen.findByLabelText('예약 9 주기')
    fireEvent.click(screen.getByRole('button', { name: '예약 9 삭제' }))
    await screen.findByText('등록된 정기 검사가 없습니다.')
    expect(request).toHaveBeenCalledWith('/analyses/schedules/9', expect.objectContaining({ method: 'DELETE' }))
  })

  it('패널을 떠나면 업로드 요청을 취소하고 늦은 응답으로 화면을 이동하지 않는다', async () => {
    let resolve
    const request = vi.fn((path, options) => options?.method === 'POST' ? new Promise((done) => { resolve = done }) : Promise.resolve([]))
    const { unmount, props } = open({ request })
    fireEvent.click(screen.getByRole('button', { name: '서버 앱 경로' }))
    fireEvent.change(screen.getByRole('combobox', { name: /^(결과를 저장할 대상|검사할 서버)/ }), { target: { value: '1' } })
    fireEvent.change(screen.getByLabelText('서버 앱 절대 경로'), { target: { value: '/opt/orders' } })
    fireEvent.click(screen.getByRole('button', { name: '검사 시작' }))
    await waitFor(() => expect(resolve).toBeDefined())
    const signal = request.mock.calls.find(([, options]) => options?.method === 'POST')[1].signal
    unmount(); expect(signal.aborted).toBe(true)
    await act(async () => resolve({ id: 99 }))
    expect(props.onJobQueued).not.toHaveBeenCalled()
  })
})

describe('Git 저장소와 의존성 파일 입력', () => {
  it('Git 저장소 주소·브랜치·토큰을 JSON으로 보내고 토큰은 응답 뒤 비운다', async () => {
    const queued = { id: 9, asset_id: 2, scan_scope: 'source-git:orders', status: 'QUEUED', input_type: 'git' }
    const request = vi.fn(async (path, options) => options?.method === 'POST' ? queued : [])
    const onJobQueued = vi.fn()
    render(<AnalysisTargets mode="zip" assets={assets} canEdit request={request} onJobQueued={onJobQueued} />)
    fireEvent.click(screen.getByRole('button', { name: 'Git 저장소' }))
    fireEvent.change(screen.getByRole('combobox', { name: /^결과를 저장할 대상/ }), { target: { value: '2' } })
    fireEvent.change(screen.getByLabelText('프로젝트 이름'), { target: { value: 'orders' } })
    fireEvent.change(screen.getByLabelText('저장소 주소 (https)'), { target: { value: 'http://github.com/org/orders' } })
    fireEvent.click(screen.getByRole('button', { name: '검사 시작' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('https://')
    expect(request.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false)
    fireEvent.change(screen.getByLabelText('저장소 주소 (https)'), { target: { value: 'https://github.com/org/orders' } })
    fireEvent.change(screen.getByLabelText('브랜치 또는 태그'), { target: { value: 'release/1.2' } })
    fireEvent.change(screen.getByLabelText('접근 토큰 (비공개 저장소)'), { target: { value: 'ghp_secret' } })
    fireEvent.click(screen.getByRole('button', { name: '검사 시작' }))
    await waitFor(() => expect(onJobQueued).toHaveBeenCalledWith(queued))
    const [path, options] = request.mock.calls.find(([, options]) => options?.method === 'POST')
    expect(path).toBe('/analyses/assets/2/git')
    expect(JSON.parse(options.body)).toEqual({ repository_url: 'https://github.com/org/orders', project_name: 'orders', ref: 'release/1.2', access_token: 'ghp_secret' })
    expect(screen.getByLabelText('접근 토큰 (비공개 저장소)')).toHaveValue('')
    expect(request.mock.calls.some(([path]) => path === '/analyses/schedules')).toBe(false)
  })

  it('Git 프로젝트 이력에서 넘어오면 저장소 입력을 이어받고 파일 입력은 의존성 파일도 받는다', () => {
    render(<AnalysisTargets mode="zip" assets={assets} canEdit request={vi.fn(async () => [])} onJobQueued={vi.fn()} initialAssetId={2} initialScope="source-git:orders" initialProjectName="orders" initialGitUrl="https://github.com/org/orders" initialGitRef="main" />)
    expect(screen.getByLabelText('저장소 주소 (https)')).toHaveValue('https://github.com/org/orders')
    expect(screen.getByLabelText('브랜치 또는 태그')).toHaveValue('main')
    expect(screen.getByLabelText('프로젝트 이름')).toHaveValue('orders')
    fireEvent.click(screen.getByRole('button', { name: '소스 ZIP · 의존성 파일' }))
    expect(screen.getByLabelText('소스 ZIP 또는 의존성 파일').getAttribute('accept')).toContain('.lock')
    expect(screen.queryByLabelText('저장소 주소 (https)')).not.toBeInTheDocument()
  })
})

describe('오류 문구와 주소 정리', () => {
  it('검증 오류 목록을 필드 이름과 함께 한 문장으로 만들고 주소에서 스킴·경로·포트를 분리한다', async () => {
    const { describeDetail, splitAddress } = await import('./App')
    expect(describeDetail([{ loc: ['body', 'ip_address'], msg: 'Value error, 서버 주소는 IP 주소나 도메인 이름이어야 합니다' }], 422)).toBe('서버 주소: 서버 주소는 IP 주소나 도메인 이름이어야 합니다')
    expect(describeDetail('이미 있는 번호입니다', 409)).toBe('이미 있는 번호입니다')
    expect(describeDetail(undefined, 403)).toBe('관리자만 할 수 있는 작업입니다.')
    expect(splitAddress(' https://db01.example.com/path ')).toEqual({ host: 'db01.example.com', port: null })
    expect(splitAddress('192.168.0.10:2222')).toEqual({ host: '192.168.0.10', port: 2222 })
    expect(splitAddress('')).toEqual({ host: '', port: null })
  })
})
