#!/usr/bin/env node
/**
 * CLA-1：斗鱼动态签名脚本（vm 执行远程下发代码）默认禁止。
 *  - 默认（未配置）：createMobileSign 明确报错，不执行任何脚本；
 *  - 显式开启（system-config.json enableDouyuSigner: true）：行为与改动前一致（本测试用自建 fixture 验证，
 *    不访问斗鱼官网）；
 *  - 关闭时 resolveRoom 对有效房间引用返回明确错误描述（不执行脚本、不发请求）。
 * 运行： node scripts/test-douyu-signer.mjs
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const DATA_DIR = mkdtempSync(join(tmpdir(), 'iptv-douyu-signer-'))
process.env.mdataDir = DATA_DIR

const { reloadConfig } = await import('../config.js')
const { createMobileSign, resolveRoom, DouyuError, clearResolveCache, ANONYMOUS_DID } = await import('../extractors/douyu-live/api.js')

// 自建签名函数 fixture：只读入参、返回可过白名单校验的查询串（与斗鱼真实 crptext 无关，不执行外部脚本）
const FIXTURE = `function ub98484234(room, did, tt) {
  // 填充注释保证长度 >= 100 字符（真实 crptext 都是数百字节起步）
  /* ----------------------------------------------- */
  return 'v=2&did=' + did + '&tt=' + tt + '&sign=' + CryptoJS.MD5('fixture-' + room + '-' + did + '-' + tt);
}`

let passed = 0
const check = async (name, fn) => { await fn(); passed++; console.log('  ✅ ' + name) }

console.log('斗鱼动态签名默认禁止测试')

try {
  await check('默认（未配置）：createMobileSign 明确拒绝，不执行脚本', () => {
    assert.throws(() => createMobileSign(FIXTURE, '9999'), error => {
      assert.ok(error instanceof DouyuError)
      assert.match(error.message, /签名已禁用/)
      assert.match(error.message, /不是安全边界/)
      return true
    })
  })

  await check('默认：resolveRoom 对有效房间引用返回明确错误（不发请求、不执行远程脚本）', async () => {
    const r = await resolveRoom('douyu-9999', { fetchImpl: async () => { throw new Error('不应发请求') } })
    assert.equal(r.url, '')
    assert.match(r.desc, /签名已禁用/)
  })

  await check('显式开启 enableDouyuSigner: true 后：签名函数可用（自建 fixture，不访问官网）', async () => {
    writeFileSync(join(DATA_DIR, 'system-config.json'), JSON.stringify({ enableDouyuSigner: true }))
    reloadConfig()
    const params = createMobileSign(FIXTURE, '9999', ANONYMOUS_DID, 1700000000)
    assert.equal(params.get('did'), ANONYMOUS_DID)
    assert.equal(params.get('tt'), '1700000000')
    assert.match(params.get('sign') || '', /^[0-9a-f]{32}$/)
    // 非法结果照样拒（字段白名单校验仍生效）
    assert.throws(() => createMobileSign(FIXTURE.replace("'v=2&did='", "'v=oops&did='"), '9999'), /不完整/)
  })

  await check('改回默认（false）：再次拒绝', async () => {
    writeFileSync(join(DATA_DIR, 'system-config.json'), JSON.stringify({ enableDouyuSigner: false }))
    reloadConfig()
    assert.throws(() => createMobileSign(FIXTURE, '9999'), /签名已禁用/)
  })

  console.log(`\n全部通过（${passed} 项）`)
} finally {
  clearResolveCache()
  rmSync(DATA_DIR, { recursive: true, force: true })
}
process.exit(0)
