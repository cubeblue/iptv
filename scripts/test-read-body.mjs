#!/usr/bin/env node
/**
 * CLA-1：readBody 请求体限流（app.js）+ isLoopbackRequest 判定 + 空密码管理门。
 *
 * 用真实 HTTP 服务验证：
 *   1) chunked（无 Content-Length）小请求正常读取（含中文多字节）；
 *   2) 超限请求回 413 且剩余上传被抽干、服务照常可用（内存不再累积）；
 *   3) isLoopbackRequest 纯函数判定：来源回环 + 无转发头 + 回环 Host 才算本机形状；
 *      转发头指向外网 / 非回环 Host 一律拒绝。（注意：该函数已不作为管理门鉴权——
 *      本地反代可伪造三要素，空密码管理门整体关闭，见第 4 项与 test-admin-gate.mjs）
 *   4) 真实应用（未设密码）：/admin 与 /api 一律 403——含回环来源+回环 Host 的反代形状。
 * 运行： node scripts/test-read-body.mjs
 */
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const DATA_DIR = mkdtempSync(join(tmpdir(), 'iptv-read-body-'))
process.env.mdataDir = DATA_DIR
process.env.mblank = 'true'

// import app.js 会启动应用自身，先占一个空闲端口（同 test-subscription-headers 的做法）
async function freePort() {
  const probe = http.createServer()
  await new Promise((resolve, reject) => { probe.once('error', reject); probe.listen(0, '127.0.0.1', resolve) })
  const selected = probe.address().port
  await new Promise((resolve, reject) => probe.close(error => error ? reject(error) : resolve()))
  return selected
}
process.env.mport = String(await freePort())

const { readBody, MAX_BODY_BYTES, isLoopbackRequest } = await import('../app.js')

let passed = 0
const check = async (name, fn) => { await fn(); passed++; console.log('  ✅ ' + name) }

console.log('readBody 限流与后台 fail-closed 判定测试')

// 真实 HTTP 服务：/echo 回读请求体；超限回 413
const server = http.createServer(async (req, res) => {
  try {
    const body = await readBody(req)
    res.writeHead(200, { 'Content-Type': 'text/plain' })
    res.end(`len:${Buffer.byteLength(body)}`)
  } catch (error) {
    res.writeHead(error.statusCode === 413 ? 413 : 400, { 'Content-Type': 'text/plain' })
    res.end(String(error.message))
  }
})
await new Promise(r => server.listen(0, '127.0.0.1', r))
const PORT = server.address().port

function rawPost(body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port: PORT, path: '/echo', method: 'POST', headers }, res => {
      const chunks = []
      res.on('data', c => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }))
    })
    req.once('error', reject)
    req.end(body)
  })
}

// 启动后的真实应用（未设密码）：/admin 与 /api 一律 403（回环来源+回环 Host 也不行）
const appPort = Number(process.env.mport)
function appRequest(path, host) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port: appPort, path, method: 'GET', headers: { Host: host } }, res => {
      const chunks = []
      res.on('data', c => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }))
    })
    req.once('error', reject)
    req.end()
  })
}

let failed = false
try {
  await check('chunked 小请求正常读取（多字节中文不截断）', async () => {
    const r = await rawPost('{"name":"咪咕测试频道"}', { 'Transfer-Encoding': 'chunked' })
    assert.equal(r.status, 200)
    assert.equal(r.body, 'len:29')
  })

  await check('超限请求（无 Content-Length，按实际字节数）回 413，服务照常', async () => {
    const big = Buffer.alloc(MAX_BODY_BYTES + 1024, 0x61)
    const r = await rawPost(big, { 'Transfer-Encoding': 'chunked' })
    assert.equal(r.status, 413)
    assert.match(r.body, /请求体过大/)
    const after = await rawPost('ok')
    assert.equal(after.status, 200, '超限后同一服务仍可正常处理请求')
  })

  await check('isLoopbackRequest：回环来源+回环 Host 才是本机；转发头/Host 任一不对即拒绝', () => {
    const req = (remote, host, xff) => ({ socket: { remoteAddress: remote }, headers: { host, ...(xff ? { 'x-forwarded-for': xff } : {}) } })
    assert.equal(isLoopbackRequest(req('127.0.0.1', '127.0.0.1:1905')), true)
    assert.equal(isLoopbackRequest(req('::1', 'localhost:1905')), true)
    assert.equal(isLoopbackRequest(req('::ffff:127.0.0.1', '[::1]:1905')), true)
    assert.equal(isLoopbackRequest(req('192.168.1.5', '127.0.0.1:1905')), false, '来源非回环')
    assert.equal(isLoopbackRequest(req('127.0.0.1', '127.0.0.1:1905', '203.0.113.9')), false, '转发头指向外网')
    assert.equal(isLoopbackRequest(req('127.0.0.1', '127.0.0.1:1905', '127.0.0.1, 10.0.0.1')), false, '转发链里有非回环')
    assert.equal(isLoopbackRequest(req('127.0.0.1', 'evil.example:1905')), false, 'Host 非回环（防 DNS 重绑定域名指到 127.0.0.1）')
    assert.equal(isLoopbackRequest(req('127.0.0.1', '192.168.1.5:1905')), false, 'Host 是局域网 IP')
    assert.equal(isLoopbackRequest(req('127.0.0.1', '')), false, 'Host 缺失')
  })

  await check('真实应用（未设密码）：/admin 与 /api 一律 403（回环来源+回环 Host 的反代形状也不放行）', async () => {
    const admin = await appRequest('/admin', `127.0.0.1:${appPort}`)
    assert.equal(admin.status, 403, '空密码：回环 Host 的 /admin 也必须 403')
    assert.match(admin.body, /未设置访问密码/)
    const api = await appRequest('/api/channels', `localhost:${appPort}`)
    assert.equal(api.status, 403, '空密码：/api 一律 403')
    const lanHost = await appRequest('/admin', `192.168.50.2:${appPort}`)
    assert.equal(lanHost.status, 403, '非回环 Host 同样 403')
    const apiLan = await appRequest('/api/channels', `192.168.50.2:${appPort}`)
    assert.equal(apiLan.status, 403)
  })

  console.log(`\n全部通过（${passed} 项）`)
} catch (error) {
  failed = true
  console.error(error)
} finally {
  server.closeAllConnections?.(); server.close()
  rmSync(DATA_DIR, { recursive: true, force: true })
}
process.exit(failed ? 1 : 0)
