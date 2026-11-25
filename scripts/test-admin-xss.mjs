#!/usr/bin/env node
/**
 * CLA-1：后台页面（web/admin.html）存储型 XSS 防护回归。
 *
 * 1) 从页面里提取**真实发布**的 escapeHtml / escapeInlineJs 实现（vm 求值，只注入这两个纯函数），
 *    用恶意频道名/分组名验证转义在各自上下文（HTML 文本 / HTML 属性 / 属性内 JS 字符串）下不可逃逸；
 * 2) 静态断言已知注入点已修复：频道列表用 textContent、外部源详情/分组列表的插值全部经转义。
 * 运行： node scripts/test-admin-xss.mjs
 */
import assert from 'node:assert/strict'
import vm from 'node:vm'
import { readFileSync } from 'node:fs'

const html = readFileSync(new URL('../web/admin.html', import.meta.url), 'utf8')

// 只提取页面里发布的两个转义函数（其余页面代码不进 vm，不存在平台行为模拟问题）
function extractFunction(source, name) {
  const start = source.indexOf(`function ${name}(s) {`)
  assert.ok(start > 0, `未找到 ${name}`)
  const brace = source.indexOf('{', start)
  let depth = 0
  let end = brace
  for (let i = brace; i < source.length; i++) {
    if (source[i] === '{') depth++
    else if (source[i] === '}') { depth--; if (depth === 0) { end = i + 1; break } }
  }
  return source.slice(start, end)
}

const sandbox = {}
vm.createContext(sandbox)
vm.runInContext(`${extractFunction(html, 'escapeHtml')}\n${extractFunction(html, 'escapeInlineJs')}\nthis.escapeHtml = escapeHtml; this.escapeInlineJs = escapeInlineJs;`, sandbox)
const escapeHtml = sandbox.escapeHtml
const escapeInlineJs = sandbox.escapeInlineJs

let passed = 0
const check = (name, fn) => { fn(); passed++; console.log('  ✅ ' + name) }

console.log('后台存储型 XSS 防护测试')

const LINE_SEP = String.fromCharCode(0x2028) + 'line' + String.fromCharCode(0x2029) + 'break'
const LINE_BREAK_RE = new RegExp('\\r|\\n|\\u2028|\\u2029', 'g')
const PAYLOADS = [
  '<img src=x onerror=alert(1)>',
  '<script>fetch("/api/system-config")</script>',
  `"><svg/onload=alert(1)>`,
  `x');alert(1)//`,
  `x" onmouseover="alert(1)`,
  `&quot;<b>bold</b>`,
  `\`\${alert(1)}\``,
  `'\"\\`,
  LINE_SEP,
  'CCTV1 综合',
]

check('escapeHtml：HTML 文本/属性上下文不可逃逸，正常中文名原样保留', () => {
  for (const payload of PAYLOADS) {
    const escaped = escapeHtml(payload)
    assert.ok(!escaped.includes('<'), `「${payload}」转义后不应含 <`)
    assert.ok(!escaped.includes('>'), `「${payload}」转义后不应含 >`)
    assert.ok(!escaped.includes('"'), `「${payload}」转义后不应含裸双引号`)
    assert.ok(!escaped.includes("'"), `「${payload}」转义后不应含裸单引号`)
  }
  assert.equal(escapeHtml('CCTV1 综合'), 'CCTV1 综合')
})

check('escapeInlineJs：HTML 属性内 JS 单引号字符串上下文不可逃逸（实体在 JS 解析前解码也出不去）', () => {
  for (const payload of PAYLOADS) {
    const value = escapeInlineJs(payload)
    // 模拟浏览器完整解析链：HTML 属性实体解码（单遍，浏览器不会对解码产物再解码）→ JS 单引号字符串
    const attrDecoded = value.replace(/&(amp|lt|gt|quot|#39);/g, (_, name) => ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" }[name]))
    let parsed
    try {
      parsed = vm.runInNewContext(`'${attrDecoded}'`)
    } catch (error) {
      assert.fail(`「${payload}」转义后在 JS 字符串里解析失败：${error.message}`)
    }
    assert.equal(parsed, payload.replace(LINE_BREAK_RE, ' '), `「${payload}」往返值应一致`)
    // 不能含有未转义的引号（HTML 属性边界与 JS 字符串边界都出不去）
    assert.ok(!/[^\\]'/.test(value), `「${payload}」不应含未转义单引号`)
    assert.ok(!/[^\\]"/.test(value), `「${payload}」不应含未转义双引号`)
  }
  assert.equal(escapeInlineJs('CCTV1 综合'), 'CCTV1 综合')
})

// ---- 已知注入点的静态回归：防止有人改回 innerHTML 直插 ----
check('频道列表用 textContent 渲染（不再 innerHTML 直插频道名）', () => {
  const listFn = html.slice(html.indexOf('function renderChannelList()'))
  assert.match(listFn, /channelDiv\.textContent = channel\.name/)
  assert.ok(!/channelDiv\.innerHTML = channel\.name/.test(listFn), 'channelDiv 不得再用 innerHTML 直插频道名')
})

check('外部源详情与分组列表的动态值全部经转义', () => {
  const detail = html.slice(html.indexOf('function renderExternalDetail('), html.indexOf('function renderSourceProfilesRow('))
  assert.match(detail, /\$\{escapeHtml\(source\.name \|\| '未命名源'\)\}/)
  assert.match(detail, /value="\$\{escapeHtml\(source\.name \|\| ''\)\}"/)
  assert.match(detail, /value="\$\{escapeHtml\(source\.webUrl \|\| ''\)\}"/)
  assert.match(detail, /value="\$\{escapeHtml\(source\.subscriptionUrl \|\| ''\)\}"/)
  assert.match(detail, /value="\$\{escapeHtml\(source\.m3u8Url \|\| ''\)\}"/)
  assert.ok(!/value="\$\{source\.(name|webUrl|subscriptionUrl|m3u8Url)\s*\|\|/.test(detail), '表单 value 不得再直接插值')

  const groupSelect = html.slice(html.indexOf('function renderGroupSelect('), html.indexOf('function selectExternalSource('))
  assert.match(groupSelect, /value="\$\{escapeHtml\(group\)\}"[^]*?>\$\{escapeHtml\(group\)\}<\/option>/)
  assert.ok(!/`<option value="\$\{group\}"[^]*?>\$\{group\}<\/option>`/.test(groupSelect))
})

check('分组导航/分组列表/频道行的名字插值全部经转义或 textContent', () => {
  assert.match(html, /navItem\.innerHTML = `\$\{escapeHtml\(category\.name\)\}<span/)
  const groups = html.slice(html.indexOf('function renderGroupLists('), html.indexOf('function groupSelectItemMarkup('))
  assert.match(groups, /\$\{escapeHtml\(group\.name\)\}/)
  assert.ok(!/<span>\$\{group\.name\}/.test(groups))
  // 频道行内联处理器参数走 escapeInlineJs（JS 字符串上下文）
  const channels = html.slice(html.indexOf('container.innerHTML = `\n                    <div class="my-playlist-channels">'))
  assert.match(channels, /data-channel-id="\$\{escapeHtml\(channel\.id\)\}"/)
  assert.match(channels, /showChannelDetail\('\$\{escapeInlineJs\(channel\.id\)\}'/)
  assert.match(channels, /restoreChannel\('\$\{escapeInlineJs\(channel\.id\)\}', '\$\{escapeInlineJs\(group\.name\)\}'\)/)
})

console.log(`\n全部通过（${passed} 项）`)
process.exit(0)
