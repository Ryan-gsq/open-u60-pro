// Real console modules, with delayed local responses crossing a Lock boundary.
const assert = require('node:assert/strict');
const {launchChrome}=require('./browser.cjs');
const {start,watchApiResponses,releaseResponse} = require('./fixture.cjs');
(async () => {
  const fixture = await start(({url}, reply) => {
    if (url === '/api/mihomo/status') reply({installed:true, configured:true, running:true});
    else if (url === '/api/mihomo/profiles') reply({selected:'abc', profiles:[{id:'abc', name:'Private profile', remote:true}]});
    else return false;
    return true;
  });
  const browser = await launchChrome();
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await watchApiResponses(page);
  await page.addInitScript(() => sessionStorage.setItem('openu60.session', 'fixture-session'));
  const ready = async () => {
    if (page.url().startsWith(fixture.url)) await page.reload();
    else await page.goto(`${fixture.url}/#network/mihomo`);
    await page.locator('.mihomo-profile').waitFor();
  };
  const lock = async () => {
    await page.locator('#signout').click();
    await page.waitForFunction(() => OpenU60Console.locked);
  };
  try {
    await ready();
    const [profile] = await Promise.all([
      fixture.holdRequest('GET','/api/mihomo/profiles/abc'),
      page.locator('.mihomo-profile').getByRole('button',{name:'Edit',exact:true}).click(),
    ]);
    await lock();
    await releaseResponse(page,profile,{name:'Private profile', source_type:'remote', url:'https://example.invalid/?token=private-fixture'});
    assert.equal(await page.locator('#mihomo-profile-url').inputValue(),'');
    assert.equal(await page.locator('#mihomo-profile-url').isHidden(),true);

    await ready();
    const [extensions] = await Promise.all([
      fixture.holdRequest('GET','/api/mihomo/extensions'),
      page.getByRole('button',{name:'Edit Merge & Script',exact:true}).click(),
    ]);
    await lock();
    await releaseResponse(page,extensions,{merge:'private-fixture-merge', script:'private-fixture-script'});
    assert.equal(await page.locator('#mihomo-merge').inputValue(),'');
    assert.equal(await page.locator('#mihomo-script').inputValue(),'');
    assert.equal(await page.locator('#mihomo-merge').isHidden(),true);

    await ready();
    const [tab,dashboard] = await Promise.all([
      page.waitForEvent('popup'), fixture.holdRequest('POST','/api/mihomo/dashboard'),
      page.getByRole('button',{name:'Open Zashboard',exact:true}).click(),
    ]);
    await lock();
    await Promise.all([
      tab.waitForEvent('close'),
      releaseResponse(page,dashboard,{url:'/ui/mihomo/dashboard/#/proxies'}),
    ]);
    assert.ok(fixture.requests.filter(r=>r.url==='/api/auth/logout').length >= 3);
    assert.deepEqual(errors,[]);
    console.log('Passed: delayed private editors and dashboard grants cannot reopen after Lock; Lock sends server logout.');
  } finally { await browser.close(); await fixture.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});
