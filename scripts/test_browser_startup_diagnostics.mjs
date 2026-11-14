// Called by the existing driver --self-test branch. Only in-memory fake I/O.
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {EventEmitter} from 'node:events';
import {createStartupDiagnostics,createStderrMarkerScanner,startupObserve,fitStartupDiagnosticBudget} from './browser_startup_diagnostics.mjs';
const text=value=>JSON.stringify(value,null,2)+'\n';
const bytes=value=>Buffer.byteLength(text(value));
const clone=value=>JSON.parse(JSON.stringify(value));
const marker=Buffer.from('Remote debugging pipe file descriptors are not open.');
const secret='synthetic-private-token:https://user:password@private.invalid/path?secret=1';
export async function testStartupDiagnostics({CDP,fitTCPDiagnosticBudget}) {
  let cases=0,budgetCases=0;const budgetOutcomes={};
  function fixture(observerTransform=x=>x) {
    let now=0,next=0;const timers=new Map(),arms=[],cleared=[],writes=[],callbacks=[];
    const input=new EventEmitter(),output=new EventEmitter();
    Object.assign(input,{writable:true,writableEnded:false,destroyed:false,writableLength:0});
    Object.assign(output,{readable:true,readableEnded:false,destroyed:false,readableFlowing:true});
    let writeReturn=true,writeError;
    input.write=(frame,cb)=>{writes.push(frame);if(cb)callbacks.push(cb);if(writeError)throw writeError;return writeReturn;};
    const observer=createStartupDiagnostics('v24.22.2',0,()=>now);
    const Class=vm.runInNewContext('('+CDP.toString()+')',{Buffer,assert,MAX_PACKET:16*1024*1024,startupObserve,
      setTimeout(fn,ms){const id=++next;arms.push(ms);timers.set(id,fn);return id;},clearTimeout(id){cleared.push(id);timers.delete(id);}});
    const client=new Class(input,output,observerTransform(observer));
    return {client,input,output,observer,timers,arms,cleared,writes,callbacks,
      at(t){now=t;},setReturn(v){writeReturn=v;},setThrow(e){writeError=e;},
      fire(){const [id,fn]=[...timers][0];timers.delete(id);fn();},
      data(value){output.emit('data',Buffer.from(JSON.stringify(value)+'\0'));},
      raw(value){output.emit('data',Buffer.from(value));}};
  }
  async function callCase(mode) {
    const f=fixture(mode==='observer_fault'?()=>new Proxy({incomplete(){}},{get(){throw new Error(secret);}}):undefined);
    const err=Object.assign(new Error(secret),{code:secret});
    if(mode==='sync_throw')f.setThrow(err);
    if(mode==='backpressure')f.setReturn(false);
    const outcome=f.client.call('Browser.getVersion').then(value=>({value}),error=>({error}));
    if(mode==='sync_throw') {
      assert.equal((await outcome).error,err);assert.equal(f.client.pending.size,1);assert.equal(f.timers.size,1);f.at(10000);f.fire();
    }else if(mode==='callback_error') {
      f.callbacks[0](err);assert.equal(f.client.pending.size,1);assert.equal(f.timers.size,1);
      f.input.emit('error',err);assert.equal((await outcome).error,err);
    }else if(['end','input_error','output_error','exit'].includes(mode)) {
      if(mode==='end')f.output.emit('end');
      else if(mode==='exit')f.client.close(err,'child_exit');
      else (mode==='input_error'?f.input:f.output).emit('error',err);
      assert((await outcome).error);
    }else if(['null','primitive','malformed'].includes(mode)) {
      f.raw(mode==='null'?'null\0':mode==='primitive'?'3\0':'{bad\0');
      if(mode==='primitive'){assert.equal(f.client.pending.size,1);f.at(10000);f.fire();}
      assert((await outcome).error);
    }else if(['before','same_tick_response_first'].includes(mode)) {
      f.at(mode==='before'?9999:10000);f.data({id:1,result:{product:'Chrome/157.0.8103.50',revision:'@'+'a'.repeat(40)}});
      assert((await outcome).value);assert.equal(f.timers.size,0);
      f.data({id:1,result:{product:'Chrome/157.0.8103.50'}}); // Duplicate stays diagnostic-only.
    }else {
      if(mode==='partial')f.raw('{"id":');
      f.at(10000);f.fire();assert.match((await outcome).error.message,/CDP timeout/);
      if(mode==='same_tick_timeout_first'||mode==='after') {
        f.at(mode==='after'?10001:10000);f.data({id:1,result:{product:'Chrome/157.0.8103.50'}});
        assert.equal(f.observer.snapshot(f.client).get_version.late_responses,1);
      }
    }
    assert.deepEqual(f.arms,[10000]);assert.equal(f.writes.length,1);assert.equal(f.input.listenerCount('drain'),0);
    const snapshot=f.observer.snapshot(f.client);assert(!text(snapshot).includes(secret));
    if(mode==='backpressure')assert.equal(snapshot.get_version.write_return,'false');
    if(mode==='callback_error')assert.equal(snapshot.get_version.callback,'error');
    f.client.close(new Error('synthetic disposal'));cases++;
  }
  for(const mode of ['sync_throw','callback_error','backpressure','end','input_error','output_error','exit','null','primitive','malformed','before','same_tick_response_first','same_tick_timeout_first','after','partial','observer_fault'])await callCase(mode);
  {
    const f=fixture(),pending=[];for(let i=0;i<64;i++)pending.push(f.client.call('Runtime.evaluate').catch(e=>e));
    assert.match((await f.client.call('Browser.close').catch(e=>e)).message,/pending-command bound/);
    assert.equal(f.client.next,64);assert.equal(f.writes.length,64);assert.equal(f.arms.length,64);
    f.client.close(new Error('synthetic close'));await Promise.all(pending);
    assert.match((await f.client.call('Browser.close').catch(e=>e)).message,/CDP is closed/);assert.equal(f.arms.length,64);cases++;
  }
  {
    const f=fixture();const p=f.client.call('Browser.getVersion').catch(e=>e);
    f.data({id:999,result:{product:secret}});assert.equal(f.client.pending.size,1);
    f.at(10000);f.fire();assert.match((await p).message,/timeout/);
    f.observer.failure(f.client);const initial=clone(f.observer.snapshot(f.client).failure);
    f.observer.cleanup({exitCode:null,signalCode:null});
    const close=f.client.call('Browser.close').catch(e=>e);
    f.at(10010);f.observer.exit();f.client.close(new Error('Chrome exited 0'),'child_exit');await close;
    f.at(10011);f.data({id:1,error:{message:secret},result:{product:'Chrome/1.2.3.4'}});
    assert.equal(f.observer.snapshot(f.client).chrome_build.cdp.version,null);
    f.observer.parentStopped();
    const snapshot=f.observer.snapshot(f.client),saved=text(snapshot);
    assert.equal(snapshot.cleanup.close.settlement,'child_exit');assert.equal(snapshot.cleanup.close_ms,null);
    assert.deepEqual(snapshot.failure,initial);
    f.at(10012);f.observer.close();assert.equal(text(snapshot),saved);
    assert.equal(f.observer.snapshot(f.client).cleanup.close_ms,10012);cases++;
  }
  for(const route of ['no_child','existing_child_error','already_exited','client_absent','client_closed']) {
    const f=fixture();
    f.observer.cleanup(route==='no_child'?undefined:{exitCode:route==='already_exited'?0:null,signalCode:null},route==='existing_child_error'?new Error(secret):undefined);
    if(route==='client_absent'||route==='client_closed')f.observer.notSent('Browser.close',route);
    assert.equal(f.observer.snapshot(f.client).cleanup.route,route);cases++;
  }
  for(const postSpawn of [false,true]) {
    const f=fixture();if(postSpawn)f.observer.spawn();f.observer.childError(Object.assign(new Error(secret),{code:'ENOENT'}));f.observer.close();
    assert.equal(f.observer.snapshot().spawn.error_stage,postSpawn?'post_spawn':'before_spawn');cases++;
  }
  for(let split=0;split<=marker.length;split++) {
    const scanner=createStderrMarkerScanner(()=>5);scanner.observe(marker.subarray(0,split));scanner.observe(marker.subarray(split));
    assert.equal(scanner.snapshot().pipe_descriptors_unavailable,1);assert(scanner.maximumRetainedBytes()<=marker.length-1);cases++;
  }
  for(const end of [4095,4096,4097,65535,65536,65537]) {
    const scanner=createStderrMarkerScanner(()=>5),buffer=Buffer.alloc(65536+marker.length,120);
    marker.copy(buffer,end-marker.length);scanner.observe(buffer);
    assert.equal(scanner.snapshot().pipe_descriptors_unavailable,end<=65536?1:0);
    assert.equal(scanner.retainedBytes(),0);assert.equal(scanner.snapshot().scanned_bytes,65536);assert.equal(scanner.snapshot().observed_bytes,buffer.length);cases++;
  }
  {
    const scanner=createStderrMarkerScanner(()=>8);scanner.observe(Buffer.concat([marker,marker]));assert.equal(scanner.snapshot().pipe_descriptors_unavailable,2);
    scanner.observe(Buffer.alloc(1,120));assert.equal(scanner.snapshot().pipe_descriptors_unavailable,2);
    const large=Buffer.alloc(8*1024*1024,120);scanner.observe(large);assert.equal(scanner.retainedBytes(),0);assert(scanner.maximumRetainedBytes()<=marker.length-1);
    scanner.observe(marker);assert.equal(scanner.snapshot().pipe_descriptors_unavailable,2);cases++;
  }
  {
    const f=fixture();const raw=Buffer.concat([Buffer.from([255,0,237,159]),Buffer.from('界'+secret),marker]);f.observer.stderr(raw);
    const snapshot=f.observer.snapshot();assert.equal(snapshot.stderr.pipe_descriptors_unavailable,1);assert.equal(snapshot.stderr.observed_bytes,raw.length);assert(!text(snapshot).includes(secret));cases++;
  }
  {
    const f=fixture();f.observer.stderr({length:70000,subarray(){throw new Error(secret);}});f.observer.stderr(Buffer.from(secret));
    assert.equal(f.observer.snapshot().stderr.scan_status,'incomplete');assert.equal(f.observer.snapshot().stderr.observed_bytes,70000+Buffer.byteLength(secret));cases++;
  }
  for(const value of [undefined,null,3,secret,'1.2.3.4\n','1.2.3.4','99999.99999.99999.99999']) {
    const f=fixture();let traversed=false;
    const info={version:value,cl:'b'.repeat(40)};Object.defineProperty(info,'command_line',{get(){traversed=true;throw new Error(secret);}});
    f.observer.netlog({constants:{clientInfo:info}});
    const snapshot=f.observer.snapshot();assert(!traversed);assert(!text(snapshot).includes(secret));
    assert.equal(snapshot.chrome_build.netlog.version_status,value===undefined?'missing':typeof value==='string'&&/^[0-9]{1,5}(\.[0-9]{1,5}){3}$/.test(value)?'valid':'invalid');cases++;
  }
  for(const same of [true,false]) {
    const f=fixture(),p=f.client.call('Browser.getVersion');f.data({id:1,result:{product:'Chrome/1.2.3.4',revision:'@'+'c'.repeat(40)}});await p;
    f.observer.netlog({constants:{clientInfo:{version:same?'1.2.3.4':'1.2.3.5',cl:'c'.repeat(40),command_line:secret}}});
    assert.equal(f.observer.snapshot().chrome_build.version_agreement,same?'match':'mismatch');cases++;
  }
  for(const value of [undefined,null,3,secret,'f'.repeat(1000),'f'.repeat(40)+'\n','@'+'f'.repeat(40),'f'.repeat(40)]) {
    const f=fixture();f.observer.netlog({constants:{clientInfo:{cl:value}}});
    const snapshot=f.observer.snapshot();assert(!text(snapshot).includes(secret));
    assert.equal(snapshot.chrome_build.netlog.revision_status,value===undefined?'missing':value==='f'.repeat(40)?'valid':'invalid');cases++;
  }
  for(const product of [null,3,secret,'Chrome/1.2.3.4\n','Chrome/'+'1'.repeat(1000)]) {
    const f=fixture(),p=f.client.call('Browser.getVersion');f.data({id:1,result:{product}});await p;
    assert.equal(f.observer.snapshot().chrome_build.cdp.version,null);assert(!text(f.observer.snapshot()).includes(secret));cases++;
  }
  for(const revision of [secret,3,'@'+'a'.repeat(40)+'\n']) {
    const f=fixture(),p=f.client.call('Browser.getVersion');f.data({id:1,result:{product:'Chrome/1.2.3.4',revision}});await p;
    assert.equal(f.observer.snapshot().chrome_build.cdp.revision,null);assert(!text(f.observer.snapshot()).includes(secret));cases++;
  }
  {
    const f=fixture(),p=f.client.call('Browser.getVersion').catch(e=>e);
    const poisoned=new Proxy({},{getOwnPropertyDescriptor(){throw new Error(secret);}});
    assert.doesNotThrow(()=>f.callbacks[0](poisoned));assert.equal(f.client.pending.size,1);
    f.input.emit('error',new Error('original transport error'));assert.match((await p).message,/original transport error/);
    assert.equal(f.observer.snapshot().status,'incomplete');cases++;
  }
  {
    const f=fixture();f.observer.netlog({constants:{clientInfo:Object.create({version:secret,cl:secret})}});
    assert.equal(f.observer.snapshot().chrome_build.netlog.version_status,'missing');
    const throwing=createStartupDiagnostics(secret,0,()=>{throw new Error(secret);});
    assert.doesNotThrow(()=>throwing.command('Browser.getVersion',1));
    const checks={automated_status:'passed'};fitStartupDiagnosticBudget(checks,throwing);
    assert.deepEqual(checks.startup_diagnostics,{schema_version:1,status:'incomplete'});assert(!text(checks).includes(secret));cases++;
  }
  {
    const f=fixture();const poisoned=new Proxy({},{getOwnPropertyDescriptor(){throw new Error(secret);}});
    assert.doesNotThrow(()=>f.observer.netlog(poisoned));assert.equal(f.observer.snapshot().status,'incomplete');
    f.at(400000);f.observer.command('Browser.getVersion',1);const snapshot=f.observer.snapshot({receivedBytes:1e20,receivedMessages:1e20,buffer:{length:1e20}});
    assert.equal(snapshot.clipped,true);assert.equal(snapshot.saturated,true);assert.equal(snapshot.get_version.deadline_ms,300000);
    assert.equal(snapshot.cleanup.received_bytes,2147483647);cases++;
  }
  // Use a maximal real snapshot: no arbitrary padding or strings enter its schema.
  const maximum=createStartupDiagnostics('v99999.99999.99999',0,()=>300000);
  maximum.command('Browser.getVersion',2147483647);maximum.command('Browser.close',2147483646);
  maximum.netlog({constants:{clientInfo:{version:'99999.99999.99999.99999',cl:'f'.repeat(40)}}});
  const fakeClient={receivedBytes:1e20,receivedMessages:1e20,buffer:{length:1e20},input:{writableLength:1e20}};
  maximum.failure(fakeClient);maximum.cleanup({exitCode:null,signalCode:null});maximum.parentStopped();
  const full=maximum.snapshot(fakeClient);
  // Conservative maximum for every closed-schema scalar, even combinations
  // that one real execution need not attain together. No extra schema keys.
  const longest={status:'incomplete',error_stage:'before_spawn',error_code:'unobserved',write_return:'unobserved',callback:'locally_handled',write_error:'unobserved',settlement:'transport_closed',route:'existing_child_error',version_status:'missing',revision_status:'missing',version_agreement:'not_comparable',scan_status:'incomplete'};
  function envelope(object) {
    for(const key of Object.keys(object)) {
      const value=object[key];
      if(value&&typeof value==='object')envelope(value);
      else if(key==='schema_version')object[key]=1;
      else if(key==='version')object[key]='99999.99999.99999.99999';
      else if(key==='revision')object[key]='f'.repeat(40);
      else if(key==='node')object[key]='v99999.99999.99999';
      else if(key in longest)object[key]=longest[key];
      else if(key.endsWith('_ms'))object[key]=300000;
      else if(typeof value==='number')object[key]=2147483647;
      else if(typeof value==='boolean'||value===null)object[key]=false;
    }
  }
  envelope(full);const fullObserver={snapshot:()=>full};
  const prototype={network_audit:{violations:[],udp_diagnostics:{details_complete:true},tcp_diagnostics:{schema_version:1,scope:'pending keys from the existing TCP audit; not packet capture',matching_basis:'source_id_event_name_latest_begin',limits:{pending_records:16,same_id_events_per_record:4,bytes:16384,relative_time_ms:300000},unfinished_key_count:16,recorded_key_count:16,omitted_key_count:0,projection_status:'complete',reason_counts:[],records:Array.from({length:16},()=>({source_id:44,event_type:'TCP_CONNECT',context:'x'.repeat(600)}))}},automated_status:'passed',startup:{received_bytes:0},error:null,pad:''};
  const originalTCP=clone(prototype.network_audit.tcp_diagnostics);
  function padded(mode,target,status) {
    let value=clone(prototype);value.automated_status=status;
    if(mode==='summary')value.network_audit.tcp_diagnostics={...originalTCP,recorded_key_count:0,omitted_key_count:16,projection_status:'summary_only',reason_counts:[{reason:'artifact_byte_bound',count:1}],records:[]};
    if(mode==='omitted')delete value.network_audit.tcp_diagnostics;
    const extra=target-bytes(value);assert(extra>=0);value.pad='界'.repeat(Math.floor(extra/3))+'x'.repeat(extra%3);
    return value;
  }
  for(const mode of ['full','summary','omitted'])for(const status of ['passed','failed']) {
    const empty={pad:''};fitStartupDiagnosticBudget(empty,fullObserver,fakeClient);const increment=bytes(empty)-bytes({pad:''});assert(increment<=4096);
    const tinyIncrement=bytes({pad:'',startup_diagnostics:{schema_version:1,status:'incomplete'}})-bytes({pad:''});
    for(const target of [262143,262144,262145,...[-1,0,1].map(d=>262144-increment+d),...[-1,0,1].map(d=>262144-tinyIncrement+d)]) {
      const legacy=padded(mode,target,status),expected=clone(legacy);fitTCPDiagnosticBudget(expected);
      const candidate=clone(legacy);fitTCPDiagnosticBudget(candidate);fitStartupDiagnosticBudget(candidate,fullObserver,fakeClient);
      const detail=candidate.startup_diagnostics;delete candidate.startup_diagnostics;
      assert.deepEqual(candidate,expected);assert.equal(bytes(candidate),bytes(expected));
      if(bytes(expected)>262144)assert.equal(detail,undefined);
      else if(detail){assert(bytes({...candidate,startup_diagnostics:detail})<=262144);assert(bytes({...candidate,startup_diagnostics:detail})-bytes(candidate)<=4096);}
      const expectedKind=bytes(expected)+increment<=262144?'full':bytes(expected)+tinyIncrement<=262144?'tiny':'omitted';
      assert.equal(detail===undefined?'omitted':Object.hasOwn(detail,'get_version')?'full':'tiny',expectedKind);
      const outcome=mode+'/'+status+'/'+expectedKind;budgetOutcomes[outcome]=(budgetOutcomes[outcome]??0)+1;
      budgetCases++;
    }
  }
  for(const observer of [{snapshot(){throw new Error(secret);}},{snapshot:()=>({raw:secret})},{snapshot:()=>({...full,raw:secret})}]) {
    const checks={network_audit:{violations:[]},automated_status:'passed'};fitStartupDiagnosticBudget(checks,observer);
    assert(!text(checks).includes(secret));assert.equal(checks.automated_status,'passed');cases++;
  }
  for(const failureCall of [1,2,3]) {
    let calls=0;const checks={automated_status:'failed',error:'original',pad:''};checks.pad='x'.repeat(262000-bytes(checks));const before=clone(checks);
    fitStartupDiagnosticBudget(checks,fullObserver,fakeClient,value=>{if(++calls===failureCall)throw new Error(secret);return text(value);});
    delete checks.startup_diagnostics;assert.deepEqual(checks,before);assert(calls>=failureCall);cases++;
  }
  assert(bytes({startup_diagnostics:full})-bytes({})<=4096);
  console.log(JSON.stringify({startup_diagnostics:'passed',cases,budget_cases:budgetCases,budget_outcomes:budgetOutcomes,maximum_schema_increment:bytes({startup_diagnostics:full})-bytes({}),isolation:'VM fake timers/in-memory streams only; no Chrome/network/subprocess/Go'}));
}
