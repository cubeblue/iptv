#!/usr/bin/env node
/**
 * CLA-1：无法固定 DNS 连接的传输必须 fail closed（含系统代理 HTTPS_PROXY）。
 * 本测试进程在 import 前设置 HTTPS_PROXY，验证：
 *   1) HLS 上游默认直连检测到系统代理 → 明确拒绝（不静默走代理、不静默绕过改直连）；
 *   2) customSourceFetch 对非白名单目标（本应走网络代理）→ 明确拒绝；
 *   3) 白名单目标仍可用固定直连（不因系统代理存在而受影响）。
 * 运行： node scripts/test-cla1-proxy-failclosed.mjs
 */
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const DATA_DIR = mkdtempSync(join(tmpdir(), 'iptv-cla1-proxy-'))
process.env.mdataDir = DATA_DIR
process.env.msafeLanAllow = '127.0.0.1'
// 必须在 import 业务模块前设置：systemProxyUrl() 在模块加载后首次调用时缓存环境变量
process.env.HTTPS_PROXY = 'http://127.0.0.1:1'

const { fetchUpstreamResponse } = await import('../utils/hlsProxy.js')
const { customSourceFetch } = await import('../utils/customSourceProxy.js')
const { safeFetchDirect } = await import('../utils/outboundGuard.js')

const server = http.createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('ok') })
await new Promise(r => server.listen(0, '127.0.0.1', r))
const BASE = `http://127.0.0.1:${server.address().port}`

let passed = 0
const check = async (name, fn) => { await fn(); passed++; console.log('  ✅ ' + name) }

console.log('CLA-1 代理传输 fail closed 测试')

try {
  await check('系统代理存在时：HLS 上游默认直连明确拒绝，不静默走代理', async () => {
    await assert.rejects(fetchUpstreamResponse(`${BASE}/x.m3u8`), /系统代理/)
  })

  await check('customSourceFetch 非白名单目标（本应走网络代理）明确拒绝', async () => {
    await assert.rejects(customSourceFetch('http://cdn.example/live/x.m3u8'), /无法固定 DNS 连接/)
  })

  await check('白名单目标仍走校验+固定直连，不受系统代理设置影响', async () => {
    const res = await customSourceFetch(`${BASE}/x.m3u8`)
    assert.equal(res.status, 200)
    assert.equal(await res.text(), 'ok')
    const direct = await safeFetchDirect(`${BASE}/x.m3u8`)
    assert.equal(direct.status, 200)
  })

  console.log(`\n全部通过（${passed} 项）`)
} finally {
  server.closeAllConnections?.(); server.close()
  rmSync(DATA_DIR, { recursive: true, force: true })
}
process.exit(0)
