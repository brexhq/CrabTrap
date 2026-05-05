import puppeteer from 'puppeteer'

const BASE = 'http://localhost:8081'
const ADMIN_TOKEN = 'admin-secret'
const MANAGER_TOKEN = 'manager-secret'

let browser
let passed = 0
let failed = 0

function assert(cond, msg) {
  if (!cond) {
    console.error(`  FAIL: ${msg}`)
    failed++
  } else {
    console.log(`  PASS: ${msg}`)
    passed++
  }
}

async function apiTest() {
  console.log('\n=== API Tests ===')

  // Test 1: Admin can assign manager to bot
  console.log('\n[Test 1] Admin assigns manager to bot')
  let res = await fetch(`${BASE}/admin/users/bot%40test.com/managers`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${ADMIN_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ manager_id: 'manager@test.com' }),
  })
  assert(res.status === 201, `POST assign manager returns 201, got ${res.status}`)

  // Test 2: Admin can list managers for bot
  console.log('\n[Test 2] Admin lists managers for bot')
  res = await fetch(`${BASE}/admin/users/bot%40test.com/managers`, {
    headers: { 'Authorization': `Bearer ${ADMIN_TOKEN}` },
  })
  assert(res.status === 200, `GET managers returns 200, got ${res.status}`)
  const managers = await res.json()
  assert(managers.length === 1, `Expected 1 manager, got ${managers.length}`)
  assert(managers[0].manager_id === 'manager@test.com', `Manager is manager@test.com`)
  assert(managers[0].bot_id === 'bot@test.com', `Bot is bot@test.com`)

  // Test 3: Manager can list managers (is assigned)
  console.log('\n[Test 3] Assigned manager can list managers')
  res = await fetch(`${BASE}/admin/users/bot%40test.com/managers`, {
    headers: { 'Authorization': `Bearer ${MANAGER_TOKEN}` },
  })
  assert(res.status === 200, `Assigned manager GET returns 200, got ${res.status}`)

  // Test 4: Manager sees only assigned bots in user list
  console.log('\n[Test 4] Manager sees filtered user list')
  res = await fetch(`${BASE}/admin/users`, {
    headers: { 'Authorization': `Bearer ${MANAGER_TOKEN}` },
  })
  assert(res.status === 200, `Manager GET /users returns 200, got ${res.status}`)
  const users = await res.json()
  assert(users.length === 1, `Manager sees 1 user, got ${users.length}`)
  assert(users[0].id === 'bot@test.com', `Manager sees bot@test.com, got ${users[0]?.id}`)

  // Test 5: Admin sees all users
  console.log('\n[Test 5] Admin sees all users')
  res = await fetch(`${BASE}/admin/users`, {
    headers: { 'Authorization': `Bearer ${ADMIN_TOKEN}` },
  })
  const allUsers = await res.json()
  assert(allUsers.length >= 3, `Admin sees >=3 users, got ${allUsers.length}`)

  // Test 6: Manager cannot assign managers
  console.log('\n[Test 6] Manager cannot assign managers')
  res = await fetch(`${BASE}/admin/users/bot%40test.com/managers`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${MANAGER_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ manager_id: 'admin@test.com' }),
  })
  assert(res.status === 403, `Manager POST assign returns 403, got ${res.status}`)

  // Test 7: Manager cannot unassign managers
  console.log('\n[Test 7] Manager cannot unassign managers')
  res = await fetch(`${BASE}/admin/users/bot%40test.com/managers/manager%40test.com`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${MANAGER_TOKEN}` },
  })
  assert(res.status === 403, `Manager DELETE unassign returns 403, got ${res.status}`)

  // Test 8: GET /admin/me/bots returns managed bots
  console.log('\n[Test 8] GET /admin/me/bots')
  res = await fetch(`${BASE}/admin/me/bots`, {
    headers: { 'Authorization': `Bearer ${MANAGER_TOKEN}` },
  })
  assert(res.status === 200, `GET /me/bots returns 200, got ${res.status}`)
  const bots = await res.json()
  assert(bots.length === 1, `Manager has 1 bot, got ${bots.length}`)
  assert(bots[0].id === 'bot@test.com', `Bot is bot@test.com`)

  // Test 9: User detail includes managers
  console.log('\n[Test 9] User detail includes managers array')
  res = await fetch(`${BASE}/admin/users/bot%40test.com`, {
    headers: { 'Authorization': `Bearer ${ADMIN_TOKEN}` },
  })
  const botDetail = await res.json()
  assert(Array.isArray(botDetail.managers), `managers is array`)
  assert(botDetail.managers.length === 1, `1 manager in detail, got ${botDetail.managers?.length}`)

  // Test 10: Admin can unassign manager
  console.log('\n[Test 10] Admin unassigns manager')
  res = await fetch(`${BASE}/admin/users/bot%40test.com/managers/manager%40test.com`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${ADMIN_TOKEN}` },
  })
  assert(res.status === 200, `DELETE unassign returns 200, got ${res.status}`)

  // Verify unassignment
  res = await fetch(`${BASE}/admin/users/bot%40test.com/managers`, {
    headers: { 'Authorization': `Bearer ${ADMIN_TOKEN}` },
  })
  const remaining = await res.json()
  assert(remaining.length === 0, `No managers remaining after unassign`)

  // Test 11: Manager no longer sees bot in user list
  console.log('\n[Test 11] Manager sees empty list after unassignment')
  res = await fetch(`${BASE}/admin/users`, {
    headers: { 'Authorization': `Bearer ${MANAGER_TOKEN}` },
  })
  const emptyList = await res.json()
  assert(emptyList.length === 0, `Manager sees 0 users after unassign, got ${emptyList.length}`)
}

async function browserTest() {
  console.log('\n=== Browser Tests ===')

  // Re-assign manager for browser tests
  await fetch(`${BASE}/admin/users/bot%40test.com/managers`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${ADMIN_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ manager_id: 'manager@test.com' }),
  })

  browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
  const page = await browser.newPage()

  // Test 12: Admin login and navigate to user detail
  console.log('\n[Test 12] Admin login + user detail shows managers section')
  await page.goto(`${BASE}/#/`)
  await page.waitForSelector('#token')
  await page.type('#token', ADMIN_TOKEN)
  await page.click('button[type="submit"]')
  await page.waitForSelector('nav', { timeout: 5000 })

  // Navigate to users
  await page.click('a[href="#/users"]')
  await page.waitForSelector('table', { timeout: 5000 })

  // Click on bot@test.com
  const botRow = await page.waitForSelector('td >> text/bot@test.com', { timeout: 3000 }).catch(() => null)
  if (botRow) {
    await botRow.click()
  } else {
    // Try alternative: find a link/row for bot@test.com
    await page.evaluate(() => {
      const rows = document.querySelectorAll('tr')
      for (const row of rows) {
        if (row.textContent?.includes('bot@test.com')) {
          row.querySelector('td')?.click()
          break
        }
      }
    })
  }

  await new Promise(r => setTimeout(r, 1500))

  // Check for Managers section
  const pageContent = await page.content()
  const hasManagersSection = pageContent.includes('Managers')
  assert(hasManagersSection, 'User detail page has Managers section')

  const hasManagerEmail = pageContent.includes('manager@test.com')
  assert(hasManagerEmail, 'Managers section shows manager@test.com')

  // Test 13: Manager login sees filtered user list (use incognito context)
  console.log('\n[Test 13] Manager login sees only assigned bots')
  const ctx2 = await browser.createBrowserContext()
  const page2 = await ctx2.newPage()
  await page2.goto(`${BASE}/#/`)
  await page2.waitForSelector('#token', { timeout: 5000 })
  await page2.type('#token', MANAGER_TOKEN)
  await page2.click('button[type="submit"]')
  await page2.waitForSelector('nav', { timeout: 5000 })

  // Navigate to users
  await page2.click('a[href="#/users"]')
  await new Promise(r => setTimeout(r, 1500))

  const page2Content = await page2.content()
  const seesBotUser = page2Content.includes('bot@test.com')
  assert(seesBotUser, 'Manager sees bot@test.com in user list')

  const seesAdminUser = page2Content.includes('admin@test.com')
  assert(!seesAdminUser, 'Manager does NOT see admin@test.com')

  await ctx2.close()
  await browser.close()
}

async function main() {
  try {
    await apiTest()
    await browserTest()
  } catch (err) {
    console.error('Test error:', err)
    failed++
  } finally {
    if (browser) await browser.close().catch(() => {})
  }

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`)
  process.exit(failed > 0 ? 1 : 0)
}

main()
