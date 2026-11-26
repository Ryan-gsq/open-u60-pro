// Shared by the browser suites for the network extensions: serves the real
// console files, a fake dashboard stream and a caller-supplied fake API. It
// never contacts a router.
const http=require('node:http'),fs=require('node:fs'),path=require('node:path');
const assert=require('node:assert/strict');
const envelope=data=>({ok:true,data});
const readings={modem:envelope({operate_mode:'ONLINE'}),signal:envelope({network_type:'5G'}),wan:envelope({up:true}),wan6:envelope({up:true}),speed:envelope({}),battery:envelope({capacity:80}),device:envelope({hostname:'U60'}),clients:envelope({hosts:{},dhcp_leases:[]}),sms_capacity:envelope({})};
const send=(res,data,status=200)=>{res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(status<300?{ok:true,data}:{ok:false,error:data}));};
const overviewProfiles='/api/esim/profiles';

function serveOverviewProfiles(req,res){
  if(req.method!=='GET' || req.url!==overviewProfiles)return false;
  send(res,{profiles:[]});
  return true;
}

async function navigateToOverview(page,navigate){
  const [response]=await Promise.all([
    page.waitForResponse(response=>new URL(response.url()).pathname===overviewProfiles&&response.request().method()==='GET'),
    navigate(),
  ]);
  if(!response.ok())throw new Error(`Overview profile read returned ${response.status()}`);
  await page.getByText('No profiles stored on this eSIM.',{exact:true}).waitFor();
}

function watchApiResponses(page){
  return page.addInitScript(()=>{
    const parsed=globalThis.fixtureParsedResponses=new Map();
    const json=Response.prototype.json;
    Response.prototype.json=function(...args){
      const result=json.apply(this,args);
      if(this.url.startsWith(location.origin+'/api/')){
        const path=new URL(this.url).pathname;
        // Run after the promise continuations that consume the response.
        const parsedBody=()=>setTimeout(()=>parsed.set(path,(parsed.get(path)||0)+1),0);
        result.then(parsedBody,parsedBody);
      }
      return result;
    };
  });
}

async function releaseResponse(page,held,data,status=200){
  const previous=await page.evaluate(url=>fixtureParsedResponses.get(url)||0,held.url);
  const waiting=page.waitForResponse(response=>new URL(response.url()).pathname===held.url && response.request().method()===held.method);
  held.reply(data,status);
  const response=await waiting;
  assert.equal(response.status(),status);
  await page.waitForFunction(([url,previous])=>fixtureParsedResponses.get(url)>previous,[held.url,previous]);
}

async function assertQuiet(page,requests,milliseconds,message,action){
  const before=requests.length, sent=[];
  const record=request=>{if(new URL(request.url()).pathname.startsWith('/api/'))sent.push(`${request.method()} ${request.url()}`);};
  page.on('request',record);
  try{
    await action?.();
    await page.clock.runFor(milliseconds);
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    assert.deepEqual(sent,[],message);
    assert.equal(requests.length,before,message);
  }finally{page.off('request',record);}
}

function visibilityEvent(page,type){
  return page.evaluate(type=>(type==='visibilitychange'?document:window).dispatchEvent(new Event(type)),type);
}

async function refreshOn(page,fixture,type,url){
  const before=fixture.count('GET',url);
  const [response]=await Promise.all([
    page.waitForResponse(response=>response.url()===fixture.url+url && response.request().method()==='GET'),
    visibilityEvent(page,type),
  ]);
  assert.equal(response.status(),200);
  assert.equal(fixture.count('GET',url),before+1,`${type} reads ${url} once`);
}

// `api({method,url,body,socket},reply,fail)` returns true when it answered.
async function start(api){
  const requests=[],streams=new Set(),heldRequests=new Map();
  const server=http.createServer((req,res)=>{
    if(req.url.startsWith('/ui/mihomo/dashboard/')){res.writeHead(200,{'Content-Type':'text/html'});res.end('<!doctype html><title>Zashboard stand-in</title>');return;}
    if(!req.url.startsWith('/api/')){
      const file=req.url==='/'?'index.html':/^\/(?:ui|console\/a)\/[\w.-]+$/.test(req.url)?req.url.split('/').pop():'',full=path.join(__dirname,'..',file);
      if(!file||!fs.existsSync(full)){res.writeHead(404);res.end();return;}
      res.setHeader('Content-Type',file.endsWith('.css')?'text/css':file.endsWith('.js')?'text/javascript':'text/html');
      res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'");
      res.end(fs.readFileSync(full));return;
    }
    if(req.url.startsWith('/api/dashboard/events')){
      res.writeHead(200,{'Content-Type':'text/event-stream'});streams.add(res);res.on('close',()=>streams.delete(res));
      res.write(`event: snapshot\ndata: ${JSON.stringify({readings})}\n\n`);return;
    }
    let raw='';req.on('data',chunk=>raw+=chunk);
    req.on('end',()=>{
      const body=raw?JSON.parse(raw):null,entry={url:req.url,method:req.method,body};requests.push(entry);
      const key=`${entry.method} ${entry.url}`, hold=heldRequests.get(key);
      if(hold){
        heldRequests.delete(key);
        hold({...entry,reply:(data,status=200)=>send(res,data,status)});
        return;
      }
      const handled=api({...entry,socket:req.socket,res},data=>send(res,data),(message,status=503)=>send(res,message,status));
      if(!handled)send(res,{});
    });
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const heartbeat=setInterval(()=>{for(const res of streams)res.write(': heartbeat\n\n');},1000);
  return {
    requests,
    holdRequest(method,url){
      const key=`${method} ${url}`;
      if(heldRequests.has(key))throw new Error(`Already holding ${key}`);
      return new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>{
          heldRequests.delete(key);
          reject(new Error(`Fixture did not receive ${key}`));
        },10000).unref();
        heldRequests.set(key,entry=>{clearTimeout(timer);resolve(entry);});
      });
    },
    patch(readings){for(const stream of streams)stream.write(`event: patch\ndata: ${JSON.stringify({readings})}\n\n`);},
    url:`http://127.0.0.1:${server.address().port}`,
    count:(method,url)=>requests.filter(r=>r.method===method&&r.url===url).length,
    async close(){clearInterval(heartbeat);for(const stream of streams)stream.destroy();server.closeAllConnections();server.close();}
  };
}
module.exports={start,envelope,overviewProfiles,serveOverviewProfiles,navigateToOverview,watchApiResponses,releaseResponse,assertQuiet,visibilityEvent,refreshOn};
