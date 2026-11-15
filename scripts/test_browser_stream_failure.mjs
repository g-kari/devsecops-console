// Pure mocks only: no Socket/HTTP/child/OS pipe/Chrome, no real clock or timer.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createStreamFailureControl, STREAM_FAILURE_TEXT } from './browser_stream_failure.mjs';
const source=readFileSync(new URL('./browser_console_qa.mjs', import.meta.url),'utf8');
function sourceBetween(start, end) {
  const first=source.indexOf(start);
  assert.notEqual(first,-1,`missing production start marker: ${start}`);
  const last=source.indexOf(end,first+start.length);
  assert.notEqual(last,-1,`missing production end marker: ${end}`);
  assert(last>first, 'production fragment must be nonempty');
  return source.slice(first,last);
}
let passed=0;
async function test(name, fn){await fn();passed++;console.log(`ok ${passed} ${name}`);}
class Fake {
  constructor(){this.events=new Map();this.trace=[];this.ends=[];this.destroys=0;}
  listenerCount(name, listener){this.trace.push('count');return (this.events.get(name)??[]).filter(x=>x===listener).length;}
  on(name, listener){this.trace.push(`on:${name}`);this.events.set(name,[...(this.events.get(name)??[]),listener]);return this;}
  emit(name, ...args){const list=this.events.get(name)??[];if(name==='error'&&!list.length)throw Error('unhandled fake error');for(const fn of list)fn(...args);}
  end(bytes){this.trace.push('end');this.ends.push(bytes);this.endEffect?.();}
  destroy(...args){assert.equal(args.length,0);this.destroys++;this.destroyEffect?.();}
}
function harness(options={}) {
  const exitState={exitCode:options.exitCode}, lines=[], cancellations=[];
  let client=options.client;
  const control=createStreamFailureControl({getClient:()=>client,exitState,writeReceipt:line=>{lines.push(line);options.write?.(line);}});
  return {control,exitState,lines,cancellations,setClient(value){client=value;},installClient(effect){client={close(...args){cancellations.push(args);effect?.(...args);}};}};
}
// Execute only the actual CONNECT registration fragment, not the driver module.
function connect(h) {
  const fragment=sourceBetween("    proxy.on('connect',", "    proxy.listen(0,");
  let callback;
  const checks={blocked_browser_activity:{proxy_connects:0,attempts:[]}};
  Function('proxy','checks','networkLabel','streamFailure',fragment)({on(name,fn){assert.equal(name,'connect');callback=fn;}},checks,x=>x,h.control);
  return {checks,run:socket=>callback({url:'fake.invalid'},socket)};
}
const wire='HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n';
await test('production CONNECT wiring, exact 403, duplicate and persistent late listener',()=>{
  const h=harness(), c=connect(h), s=new Fake();
  c.run(s);c.run(s);
  assert.deepEqual(s.trace,['count','on:error','end','count']);
  assert.deepEqual(s.ends,[wire]);assert.equal(c.checks.blocked_browser_activity.proxy_connects,1);
  for(const name of ['end','finish','close'])s.emit(name);
  assert.equal(h.control.failed,false);assert.deepEqual(h.lines,[]);
  s.emit('error',{code:'EPIPE'});s.emit('error',{code:'ECONNRESET'});
  assert.equal(h.control.failed,true);assert.equal(h.exitState.exitCode,1);assert.equal(h.lines.length,1);assert.equal(s.destroys,0);
});
await test('actual stderr setup registers before data without normal end failure',()=>{
  const h=harness(), stderr=new Fake();let chromeStderrBytes=0;
  const fragment=sourceBetween('    streamFailure.registerStderr(', '    client=new CDP(');
  const bytes=Function('chrome','streamFailure','startupObserve','startupDiagnostics',`let chromeStderrBytes=0;${fragment};chrome.stderr.emit('data', {length:7});return chromeStderrBytes;`)({stderr},h.control,()=>{},null);
  assert.deepEqual(stderr.trace,['on:error','on:data']);assert.equal(bytes,7);
  stderr.emit('end');stderr.emit('close');assert.equal(h.control.failed,false);
  stderr.emit('error',{code:'EPIPE'});assert.equal(h.control.failed,true);
});
await test('end emission/throw plus recursive emit and destroy throw remain finite',()=>{
  for(const throwing of [false,true]) {
    const h=harness(), c=connect(h), s=new Fake();h.installClient();
    s.endEffect=()=>{s.emit('error',{code:'EPIPE'});if(throwing)throw {code:'ECONNRESET'};};
    s.destroyEffect=()=>{s.emit('error',{code:'EPIPE'});throw Error('private destroy');};
    c.run(s);assert.equal(s.destroys,Number(throwing));assert.equal(h.lines.length,1);assert.equal(h.cancellations.length,1);assert.equal(h.exitState.exitCode,1);
  }
  const h=harness(), s=new Fake();h.control.registerConnect(s);s.endEffect=()=>{throw {code:'EPIPE'};};
  h.control.endConnect(s,wire);assert.equal(s.destroys,1);assert.match(h.lines[0],/operation=end_throw/);
});
await test('helper checkpoint rejects before a mock flag; cancellation and receipt claims precede reentrancy',()=>{
  const h=harness(), s=new Fake();h.control.registerConnect(s);s.emit('error',{});
  let spawned=false;try{h.control.checkpoint();spawned=true;}catch(e){assert(h.control.isCancellation(e));}
  assert.equal(spawned,false);
  const x=harness(), a=new Fake(), b=new Fake();x.control.registerConnect(a);x.control.registerStderr(b);
  x.installClient(()=>{assert.equal(x.exitState.exitCode,1);b.emit('error',{code:'EPIPE'});throw Error('fake cancellation');});
  a.emit('error',{code:'ECONNRESET'});a.emit('error',{});
  assert.equal(x.cancellations.length,1);assert.equal(x.lines.length,1);
  assert.equal(x.lines[0],'FAIL browser stream role=deny_proxy_connect phase=running operation=error_event code=ECONNRESET\n');
  assert.throws(()=>x.control.checkpoint(),e=>x.control.isCancellation(e));
});
await test('all 64 wire combinations are bounded closed fields',()=>{
  let combinations=0;
  for(const role of ['deny_proxy_connect','chrome_stderr'])for(const phase of ['running','cleanup','finalizing','emitted'])for(const operation of ['error_event','end_throw'])for(const code of ['ECONNRESET','EPIPE','ERR_STREAM_DESTROYED','other']) {
    // Only CONNECT can generate end_throw in production. Exercise the formatter's
    // closed cross-product separately, and production-reachable cases below.
    const line=`FAIL browser stream role=${role} phase=${phase} operation=${operation} code=${code}\n`;
    assert(Buffer.byteLength(line)<=192);combinations++;
    if(role==='chrome_stderr'&&operation==='end_throw')continue;
    const h=harness(), s=new Fake();if(phase!=='running')h.control[phase]();
    if(role==='chrome_stderr')h.control.registerStderr(s);else h.control.registerConnect(s);
    if(operation==='end_throw'){s.endEffect=()=>{throw {code};};h.control.endConnect(s,wire);}else s.emit('error',{code});
    assert.equal(h.lines[0],line);
  }
  assert.equal(combinations,64);
});
await test('poison descriptors, coercions, raw messages and writer throws cannot undo failure',()=>{
  const poison=()=>{throw Error('must not inspect');};
  const inputs=[Object.create({code:'EPIPE'}),{get code(){return poison();}},{code:Symbol('secret')},{code:{toString:poison}},{code:'EPIPE'+'x'.repeat(10000)},new Proxy({},{getOwnPropertyDescriptor:poison}),null];
  for(const error of inputs){const h=harness({write:poison}),s=new Fake();h.control.registerConnect(s);s.emit('error',error);assert.equal(h.exitState.exitCode,1);assert.match(h.lines[0],/code=other\n$/);}
  const error={code:'EPIPE',get message(){return poison();},get stack(){return poison();},toJSON:poison,toString:poison,valueOf:poison};
  const h=harness(),s=new Fake();h.control.registerStderr(s);s.emit('error',error);assert.match(h.lines[0],/code=EPIPE\n$/);
});
await test('nonzero exit retained and helper checkpoint rejects',()=>{
  for(const code of [undefined,0,'0',2,'7']){const h=harness({exitCode:code}),s=new Fake();h.control.registerConnect(s);s.emit('error',{});assert.equal(h.exitState.exitCode,[undefined,0,'0'].includes(code)?1:code);assert.throws(()=>h.control.checkpoint());}
});
// Reuse the exact unchanged production CDP class with fake time and I/O.
const cdpSource=sourceBetween('class CDP {', '// Track only CDP interception');
const CDP=Function('startupObserve','setTimeout','clearTimeout','MAX_PACKET','assert',`${cdpSource};return CDP;`)(()=>{},()=>({fake:true}),()=>{},16*1024*1024,assert);
await test('E-S-microtask and reverse preserve actual rejection identity',async()=>{
  for(const reverse of [false,true]){
    const h=harness(),input=new Fake(),output=new Fake(),s=new Fake();input.write=()=>true;
    const client=new CDP(input,output);h.setClient(client);h.control.registerConnect(s);
    const E=new Error('legacy E');let caught;const pending=client.call('Browser.getVersion').catch(e=>{caught=e;});
    if(reverse){s.emit('error',{});input.emit('error',E);}else{input.emit('error',E);s.emit('error',{});}
    await pending;
    if(reverse)assert(h.control.isCancellation(caught));else assert.equal(caught,E);
    assert.equal(client.closed,true);assert.equal(client.pending.size,0);assert.equal(h.control.failed,true);
    // Model the catch formatting expression; this is not execution of main catch.
    const text=Function('streamFailure','STREAM_FAILURE_TEXT','scrubNetworkText','e',"return streamFailure.isCancellation(e)?STREAM_FAILURE_TEXT:scrubNetworkText(e.stack??e).slice(0, 16384);")(h.control,STREAM_FAILURE_TEXT,String,caught);
    assert.equal(text,reverse?STREAM_FAILURE_TEXT:E.stack);
  }
});
await test('preclosed client/unrelated E and normal Browser.close output_end',async()=>{
  for(const stream of [false,true]){
    const h=harness(),input=new Fake(),output=new Fake(),s=new Fake();input.write=()=>true;
    const client=new CDP(input,output);h.setClient(client);h.control.registerConnect(s);h.control.cleanup();
    let caught;const p=client.call('Browser.close').catch(e=>{caught=e;});output.emit('end');if(stream)s.emit('error',{});await p;
    assert.equal(caught.message,'CDP pipe ended');assert.equal(h.control.isCancellation(caught),false);assert.equal(h.control.failed,stream);
  }
  const h=harness(),s=new Fake();h.control.registerConnect(s);s.emit('error',{});const E=Error('filesystem fake');let fatal;await Promise.reject(E).catch(e=>{fatal=e;});assert.equal(fatal,E);assert(!h.control.isCancellation(fatal));
});
await test('cleanup CONNECTs have no cap or closure barrier',()=>{
  const h=harness(),c=connect(h);h.control.cleanup();
  for(let i=0;i<100;i++){const s=new Fake();c.run(s);assert.deepEqual(s.ends,[wire]);assert.equal(s.destroys,0);}
  assert.equal(c.checks.blocked_browser_activity.proxy_connects,100);assert.equal(h.control.failed,false);assert.deepEqual(h.lines,[]);
});
await test('status-statement model preserves a stale snapshot on late failure; not full-main serialization',()=>{
  for(const phase of ['finalizing','emitted']){
    const h=harness(),s=new Fake();h.control.registerConnect(s);h.control.finalizing();
    const checks={violations:[]},manifest={};
    const match=source.match(/    checks\.automated_status=!fatal[^\n]+/);
    assert(match, 'missing production status statement');
    const statement=match[0];
    Function('checks','fatal','streamFailure',statement)(checks,undefined,h.control);
    const bytes=JSON.stringify(checks);if(phase==='emitted')h.control.emitted();s.emit('error',{});
    manifest.automated_status=checks.automated_status;
    assert.equal(checks.automated_status,'passed');assert.equal(manifest.automated_status,'passed');assert.equal(JSON.stringify(checks),bytes);assert.equal(h.exitState.exitCode,1);assert.throws(()=>h.control.checkpoint());
  }
});
console.log(`PASS ${passed} pure mock groups (not a Chrome/Go/integration result)`);
