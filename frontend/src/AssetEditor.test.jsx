import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import AssetEditor from './AssetEditor'

const asset = { id: 1, asset_tag: 'LAB-01', name: '서버', asset_type: 'vm', ssh_port: 22, monitored: true, ip_address: '10.0.0.1', ssh_username: 'collector', sbom_count: 1, vulnerability_count: 3 }
const sboms = [{ id: 12, asset_id: 1, bom_format: 'SPDX', spec_version: '2.3', component_count: 52, dependency_count: 2, imported_at: '2026-09-15T00:00:00Z' }, { id: 13, asset_id: 2, bom_format: 'SPDX', spec_version: '2.3', component_count: 1, dependency_count: 0 }]
function open(extra = {}) {
  const props = { asset, canEdit: true, request: vi.fn(async (path, options) => options?.method === 'PATCH' ? { ...asset, ...JSON.parse(options.body) } : path === '/sboms' ? sboms : path.endsWith('/timeline') ? [] : asset), onSaved: vi.fn(), onClose: vi.fn(), onViewCve: vi.fn(), onViewSbom: vi.fn(), ...extra }
  return { ...render(<AssetEditor {...props} />), props }
}
const ready = async () => waitFor(() => expect(screen.getByRole('button', { name: '서버 변경 저장' })).toBeEnabled())
afterEach(cleanup)

describe('서버 정보 수정', () => {
  it('최신 정보 조회 후 접속 정보를 변경하고 변경한 값만 저장한다', async () => {
    const { props } = open()
    expect(screen.getByRole('button', { name: '서버 변경 저장' })).toBeDisabled()
    await ready()
    fireEvent.change(screen.getByLabelText('SSH 포트'), { target: { value: '2222' } })
    fireEvent.change(screen.getByLabelText('서버 주소 (IP 또는 도메인)'), { target: { value: '10.0.0.9' } })
    fireEvent.click(screen.getByLabelText('검사 대상으로 사용'))
    fireEvent.click(screen.getByRole('button', { name: '서버 변경 저장' }))
    await waitFor(() => expect(props.onSaved).toHaveBeenCalled())
    const [, options] = props.request.mock.calls.find(([, options]) => options?.method === 'PATCH')
    expect(JSON.parse(options.body)).toEqual({ ssh_port: 2222, ip_address: '10.0.0.9', monitored: false })
    expect(options.headers['Content-Type']).toBe('application/json')
  })

  it('조회 실패 시 오래된 값으로 저장하지 못하고 재조회한 현재 값을 보여준다', async () => {
    let calls = 0
    const request = vi.fn(async (path) => { if (path === '/sboms' || path.endsWith('/timeline')) return []; if (++calls === 1) throw new Error('연결 실패'); return { ...asset, ssh_port: 2200 } })
    open({ request })
    await screen.findByText(/서버 정보를 불러오지 못했습니다/)
    expect(screen.getByRole('button', { name: '서버 변경 저장' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '서버 정보 다시 불러오기' }))
    await ready()
    expect(screen.getByLabelText('SSH 포트')).toHaveValue(2200)
  })

  it('삭제 확인 번호가 일치할 때만 요청하며 이력 보존 거부를 표시한다', async () => {
    const request = vi.fn(async (path, options) => { if (options?.method === 'DELETE') throw new Error('검사 이력이 있는 서버는 삭제할 수 없습니다'); return path === '/sboms' || path.endsWith('/timeline') ? [] : asset })
    const { props } = open({ request })
    await ready()
    fireEvent.click(screen.getByRole('button', { name: '서버 삭제…' }))
    expect(request.mock.calls.some(([, options]) => options?.method === 'DELETE')).toBe(false)
    const remove = screen.getByRole('button', { name: '서버 영구 삭제' })
    expect(remove).toBeDisabled()
    fireEvent.change(screen.getByLabelText('삭제 확인 서버 번호'), { target: { value: 'LAB-01' } })
    fireEvent.click(remove)
    await screen.findByText(/검사 이력이 있는 서버는 삭제할 수 없습니다/)
    expect(props.onSaved).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: '삭제 취소' }))
    expect(screen.getByLabelText('서버 주소 (IP 또는 도메인)')).toHaveValue('10.0.0.1')
  })

  it('중복 저장을 막고 언마운트 후 응답을 폐기한다', async () => {
    let resolve
    const request = vi.fn((path, options) => options?.method === 'PATCH' ? new Promise((done) => { resolve = done }) : Promise.resolve(path === '/sboms' || path.endsWith('/timeline') ? [] : asset))
    const { props, unmount } = open({ request })
    await ready()
    const submit = screen.getByRole('button', { name: '서버 변경 저장' })
    fireEvent.click(submit); fireEvent.click(submit)
    const writes = request.mock.calls.filter(([, options]) => options?.method === 'PATCH')
    expect(writes).toHaveLength(1)
    unmount()
    expect(writes[0][1].signal.aborted).toBe(true)
    await act(async () => resolve(asset))
    expect(props.onSaved).not.toHaveBeenCalled()
  })

  it('조회자에게 접속 정보와 의존성 목록을 보여주되 수정과 삭제는 숨긴다', async () => {
    const { props } = open({ canEdit: false })
    await screen.findByText('10.0.0.1')
    expect(screen.queryByRole('button', { name: '서버 변경 저장' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '서버 삭제…' })).not.toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: '의존성 목록 (1)' }))
    fireEvent.click(screen.getByRole('button', { name: '목록 보기' }))
    expect(props.onViewSbom).toHaveBeenCalledWith(12)
    expect(props.request.mock.calls.every(([, options]) => !options.method)).toBe(true)
  })
})

describe('이력 포함 삭제', () => {
  it('이력 포함 삭제를 선택하면 purge 옵션으로 요청하고, 선택하지 않으면 그대로 요청한다', async () => {
    const request = vi.fn(async (path, options) => options?.method === 'DELETE' ? null : path === '/sboms' || path.endsWith('/timeline') ? [] : asset)
    const { props } = open({ request })
    await ready()
    fireEvent.click(screen.getByRole('button', { name: '서버 삭제…' }))
    fireEvent.click(screen.getByLabelText(/이력 포함 삭제/))
    fireEvent.change(screen.getByLabelText('삭제 확인 서버 번호'), { target: { value: 'LAB-01' } })
    fireEvent.click(screen.getByRole('button', { name: '서버 영구 삭제' }))
    await waitFor(() => expect(props.onSaved).toHaveBeenCalledWith(null))
    const [path] = request.mock.calls.find(([, options]) => options?.method === 'DELETE')
    expect(path).toBe('/assets/1?purge=true')
  })
})
