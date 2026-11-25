#!/usr/bin/env node
/**
 * CLA-1 管理门 HTTP 集成测试（对应审查结论：空密码「本机回环」豁免不安全——
 * 本地反向代理可把公网请求伪装成「回环来源 + 回环 Host + 无 X-Forwarded-For」）。
 *
 * 真实启动 app.js，用真实 HTTP 请求验证（两个独立进程，各自一套环境）：
 *   空密码（mpass 未设）：
 *     - /admin 403、/api/system-config 403、/proxy/web.m3u8 404（网页转发关闭）——
 *       即便请求就是反代形状：回环来源 + Host 127.0.0.1 + 无 XFF；
 *     - 用户访问令牌 /u/<token>/admin 同样 403（空密码不能借任何分支进后台）；
 *     - 纯播放页 /player 照旧公开（内容行为不变）。
 *   非空测试密码：
 *     - /密码/admin、/密码/api/system-config、/密码/player 放行；
 *     - 裸 /admin、错密码 /错密码/admin、裸 /api/system-config 拒绝；
 *     - 用户访问令牌 /u/<token>/admin 拒绝（令牌从来进不了后台）。
 *
 * 完全离线：mblank + 全部内容模块/订阅/EPG 聚合/台标托管关闭，内置源地址置空，NO_PROXY 指向回环。
 * 运行： node scripts/test-admin-gate.mjs
 */
import assert from 'node:assert/strict'
import http from 'node:http'
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const SELF = fileURLToPath(import.meta.url)
const TEST_PASS = 'gatepass'
const TOKEN = 'gate-token-000001'

async function freePort() {
  const probe = http.createServer()
  await new Promise((resolve, reject) => {
    probe.once('error', reject)
    probe.listen(0, '127.0.0.1', resolve)
  })
  const selected = probe.address().port
  await new Promise((resolve, reject) => probe.close(error => error ? reject(error) : resolve()))
  return selected
}

function request(port, path, { headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path,
      // 反代形状：回环来源 + 回环 Host + 不携带 X-Forwarded-For（正是审查证明可被伪造的形态）
      headers: { Host: `127.0.0.1:${port}`, Connection: 'close', ...headers },
    }, res => {
      const chunks = []
      res.on('data', chunk => chunks.push(chunk))
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }))
    })
    req.once('error', reject)
    req.end()
  })
}

async function waitForApp(port) {
  let lastError
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      if ((await request(port, '/favicon.ico')).status === 200) return
    } catch (error) {
      lastError = error
    }
    await new Promise(resolve => setTimeout(resolve, 20))
  }
  throw lastError || new Error('app.js 未开始监听')
}

let passed = 0
const check = async (name, fn) => { await fn(); passed++; console.log('  ✅ ' + name) }

/** 单阶段进程体：设置环境 → 启动 app.js → 跑该阶段的 HTTP 断言 */
async function runPhase(phase) {
  const DATA_DIR = process.env.ADMIN_GATE_DATA_DIR
  const PORT = Number(process.env.ADMIN_GATE_PORT)
  assert.ok(DATA_DIR && PORT, '缺少阶段环境（ADMIN_GATE_DATA_DIR / ADMIN_GATE_PORT）')

  // 必须在 import 业务模块之前设置（config.js / paths.js 在 import 时读取环境变量）
  process.env.mdataDir = DATA_DIR
  process.env.mport = String(PORT)
  process.env.mblank = 'true'
  process.env.menableMigu = 'false'
  process.env.menableBuiltInSources = 'false'
  process.env.menableBuiltInSubscriptions = 'false'
  process.env.menableEpgAggregation = 'false'
  process.env.menableLogoCache = 'false'
  process.env.mbuiltInSourcesUrl = ''
  process.env.mexternalLogoBase = ''
  process.env.mexternalLogoIndex = ''
  process.env.NO_PROXY = process.env.no_proxy = '127.0.0.1,localhost'
  delete process.env.mpass
  if (phase === 'pass') process.env.mpass = TEST_PASS

  // 一个可用用户令牌：验证「令牌进不了后台」在空密码/设密码两种形态下都成立
  writeFileSync(join(DATA_DIR, 'users.json'), JSON.stringify({
    users: [{ id: 'u_gate_test', name: '门测试用户', token: TOKEN, enabled: true, profile: '', expiresAt: null }],
  }))

  await import('../app.js')
  await waitForApp(PORT)

  try {
    if (phase === 'empty') {
      await check('空密码：/admin 拒绝——即便反代形状（回环来源+回环 Host+无 XFF）', async () => {
        const r = await request(PORT, '/admin')
        assert.equal(r.status, 403)
        assert.match(r.body, /未设置访问密码/)
      })
      await check('空密码：/api/system-config 拒绝（回环+无 XFF）', async () => {
        const r = await request(PORT, '/api/system-config')
        assert.equal(r.status, 403)
        assert.equal(JSON.parse(r.body).success, false)
      })
      await check('空密码：网页播放转发 /proxy/web.m3u8 关闭（未授权一律按“不在源里”404）', async () => {
        const r = await request(PORT, '/proxy/web.m3u8?u=' + encodeURIComponent('http://cdn.example/live.m3u8'))
        assert.equal(r.status, 404)
      })
      await check('空密码：用户令牌 /u/<token>/admin 也进不了后台（不存在另一条授权分支）', async () => {
        const r = await request(PORT, `/u/${TOKEN}/admin`)
        assert.equal(r.status, 403)
      })
      await check('空密码：纯播放页 /player 照旧公开（内容行为不变）', async () => {
        const r = await request(PORT, '/player')
        assert.equal(r.status, 200)
        assert.match(r.body, /player/)
      })
    } else {
      await check('设密码：裸 /admin 拒绝', async () => {
        const r = await request(PORT, '/admin')
        assert.equal(r.status, 403)
        assert.match(r.body, /访问需要密码/)
      })
      await check('设密码：错误密码路径 /wrongpass/admin 拒绝', async () => {
        const r = await request(PORT, '/wrongpass/admin')
        assert.equal(r.status, 403)
      })
      await check('设密码：正确密码路径 /密码/admin 放行', async () => {
        const r = await request(PORT, `/${TEST_PASS}/admin`)
        assert.equal(r.status, 200)
        assert.match(r.body, /admin/)
      })
      await check('设密码：裸 /api/system-config 拒绝', async () => {
        const r = await request(PORT, '/api/system-config')
        assert.equal(r.status, 403)
      })
      await check('设密码：/密码/api/system-config 放行', async () => {
        const r = await request(PORT, `/${TEST_PASS}/api/system-config`)
        assert.equal(r.status, 200)
        assert.equal(JSON.parse(r.body).success !== false, true)
      })
      await check('设密码：/密码/player 放行', async () => {
        const r = await request(PORT, `/${TEST_PASS}/player`)
        assert.equal(r.status, 200)
      })
      await check('设密码：用户令牌 /u/<token>/admin 仍进不了后台', async () => {
        const r = await request(PORT, `/u/${TOKEN}/admin`)
        assert.equal(r.status, 403)
      })
    }
    console.log(`\n阶段 ${phase} 全部通过（${passed} 项）`)
    process.exit(0)
  } catch (error) {
    console.error(`\n阶段 ${phase} 失败:`, error)
    process.exit(1)
  }
}

/** 主进程：为两个阶段各起一个干净进程（空密码 / 非空密码需要各自的环境与 app 实例） */
async function main() {
  const results = []
  for (const phase of ['empty', 'pass']) {
    const dataDir = mkdtempSync(join(tmpdir(), `iptv-admin-gate-${phase}-`))
    const port = await freePort()
    console.log(`--- 阶段 ${phase}（端口 ${port}）---`)
    const code = await new Promise(resolve => {
      const child = spawn(process.execPath, [SELF, phase], {
        env: { ...process.env, ADMIN_GATE_DATA_DIR: dataDir, ADMIN_GATE_PORT: String(port) },
        stdio: 'inherit',
      })
      child.on('exit', resolve)
    })
    rmSync(dataDir, { recursive: true, force: true })
    results.push([phase, code])
    if (code !== 0) break
  }
  const failed = results.filter(([, code]) => code !== 0)
  console.log(failed.length === 0
    ? `\n管理门 HTTP 测试全部通过（${results.length} 阶段）`
    : `\n管理门 HTTP 测试失败：${failed.map(([p]) => p).join(', ')}`)
  process.exit(failed.length === 0 ? 0 : 1)
}

if (process.argv[2]) {
  await runPhase(process.argv[2])
} else {
  await main()
}
