// Isolated pure-data model tests. No Chrome, application, sockets or OS pipes.
import assert from 'node:assert/strict';
import {createTCPLifecycleDiagnostics} from './browser_tcp_lifecycle_diagnostics.mjs';
import {createStartupDiagnostics,fitStartupDiagnosticBudget} from './browser_startup_diagnostics.mjs';
const key='tcp_lifecycle_diagnostics',revision='049750111b1e5c11565c792b2aeed5541f332bad';
const names=['CONNECT_JOB','TRANSPORT_CONNECT_JOB_CONNECT','TCP_CONNECT_JOB_CONNECT','CONNECT_JOB_TIMED_OUT','TRANSPORT_CONNECT_JOB_CONNECT_ATTEMPT','TCP_CONNECT_JOB_CONNECTOR_CONNECT_START','TCP_CONNECT_JOB_CONNECTOR_CONNECT_COMPLETE','TCP_CONNECT_JOB_CONNECTOR_DONE','TCP_STREAM_ATTEMPT_ALIVE','TCP_STREAM_ATTEMPT_CONNECT','TLS_STREAM_ATTEMPT_ALIVE','TLS_STREAM_ATTEMPT_CONNECT','CONNECT_JOB_SET_SOCKET','SOCKET_POOL_BOUND_TO_SOCKET','TCP_CONNECT','TCP_CONNECT_ATTEMPT','SOCKET_BYTES_SENT','SOCKET_ALIVE'];
const kinds=['SOCKET','HTTP_PROXY_CONNECT_JOB','SOCKS_CONNECT_JOB','SSL_CONNECT_JOB','TRANSPORT_CONNECT_JOB','TCP_CONNECT_JOB','TCP_STREAM_ATTEMPT','TLS_STREAM_ATTEMPT','HTTP_STREAM_JOB','HTTP_STREAM_POOL_ATTEMPT_MANAGER'];
const codes=[10,3,4,5,6,7,8,9,17,21],text=x=>JSON.stringify(x,null,2)+'\n',bytes=x=>Buffer.byteLength(text(x)),clone=x=>structuredClone(x);
export function lifecycleFixture(){
  const types=Object.fromEntries(names.map((n,i)=>[n,i+1]));Object.assign(types,{UDP_CONNECT:30,UDP_BYTES_SENT:31});
  const source=(id,type=10,start_time='1000')=>({id,type,start_time});
  const event=(name,id,type,time,phase=0,params={})=>({type:types[name],phase,time:String(time),source:source(id,type),params});
  const log={constants:{logEventTypes:types,logEventPhase:{PHASE_NONE:0,PHASE_BEGIN:1,PHASE_END:2},logSourceType:Object.fromEntries(kinds.map((x,i)=>[x,codes[i]])),netError:{ERR_ABORTED:-3,ERR_TIMED_OUT:-7,ERR_NETWORK_IO_SUSPENDED:-331}},events:[
    event('CONNECT_JOB',100,6,1000,1),event('SOCKET_ALIVE',44,10,1001,1,{source_dependency:{id:100,type:6}}),
    event('TCP_CONNECT',44,10,1002,1,{address_list:['127.0.0.1:123']}),event('TCP_CONNECT_ATTEMPT',44,10,1003,1,{address:'127.0.0.1:123'}),
    event('SOCKET_BYTES_SENT',44,10,1004,0,{byte_count:1}),event('CONNECT_JOB_SET_SOCKET',100,6,1005,0,{source_dependency:{id:55,type:10},net_error:0}),
    event('CONNECT_JOB',100,6,1006,2,{net_error:-3,cancel_reason:'Abort'}),event('SOCKET_ALIVE',44,10,1007,2)]};
  return {log,pending:new Map([['private outer',2],['private inner',3]]),names:new Map(Object.entries(types).map(([n,v])=>[v,n])),event,source};
}
export async function testTCPLifecycleDiagnostics({netlogAudit,fitTCPDiagnosticBudget}={}){
  let cases=0;const group=(name,fn)=>{fn();cases++;};
  function run(f=lifecycleFixture(),checks={synthetic:true,browser:{revision}},setup=()=>{},observer=createStartupDiagnostics('v24.22.1',0,()=>0)){
    const state=createTCPLifecycleDiagnostics();assert(state);setup(state,checks);
    fitStartupDiagnosticBudget(checks,observer,undefined,undefined,state.receipt);const before=text(checks),baseline=bytes(checks),preexisting=Object.hasOwn(checks,key);
    state.attach(checks,f.log,f.pending,f.names);const value=checks[key];if(value&&!preexisting){assert(bytes(checks)-baseline<=4096);assert(bytes(checks)<=262144);assert(!JSON.stringify(value).includes('private'));delete checks[key];assert.equal(text(checks),before);checks[key]=value;}
    return {state,checks,value,baseline};
  }
  const row=f=>run(f).value.records[0];
  const pair=(f,expected)=>{const r=row(f);assert.deepEqual([r[10],r[13]],expected);if(expected[0]!==0){for(const k of [11,14,17,18])assert.equal(r[k],null);assert.equal(r[12],0);assert.deepEqual(r[19],[]);}return r;};
  group('resolved one hop does not transfer success',()=>{const r=row(lifecycleFixture());assert.deepEqual(r.slice(0,7),[44,1,0,0,3,2,2]);assert.equal(r[10],0);assert.deepEqual(r[16],[1,0,0]);assert.equal(r[19][1][7],false);assert.equal(r[19][1][4],1);assert.equal(r[19][2][4],2);assert.equal(r[19][2][6],10);});
  group('four exact current revisions and missing/other rejected',()=>{
    for(const rev of [revision,'@'+revision,'4b3d0dabb8250b6f152d2d85d79e7706e309d087','@4b3d0dabb8250b6f152d2d85d79e7706e309d087'])assert.equal(run(undefined,{synthetic:true,browser:{revision:rev}}).value.status,0);
    for(const rev of [undefined,null,'@@'+revision,revision.toUpperCase(),'unknown']){const c={synthetic:true,browser:{revision:rev},startup_diagnostics_late:{revision}};assert.equal(run(undefined,c).value.status,2);}
  });
  group('all controller closed pairs and priorities',()=>{
    let f=lifecycleFixture();f.log.events=f.log.events.filter(e=>e.source.id!==100);f.pending=new Map([['a',1],['b',2]]);pair(f,[6,1]);
    for(const [field,value,expected] of [['type',undefined,[9,1]],['start_time',undefined,[9,1]],['type','6',[7,2]],['type',4294967302,[7,2]],['start_time',null,[7,2]],['start_time','+1000',[7,2]]]){
      f=lifecycleFixture();if(value===undefined)delete f.log.events[0].source[field];else f.log.events[0].source[field]=value;pair(f,expected);
    }
    for(const field of ['type','start_time']){f=lifecycleFixture();f.log.events[0].source[field]=field==='type'?7:'1001';delete f.log.events[5].source.start_time;pair(f,[8,3]);}
    f=lifecycleFixture();for(const e of f.log.events)if(e.source.id===100)e.source.type=7;pair(f,[7,2]);
    f=lifecycleFixture();for(const e of f.log.events)if(e.source.id===100)e.source.type=99;f.log.events[1].params.source_dependency.type=99;pair(f,[2,0]);
    f=lifecycleFixture();f.log.events[1].params={};pair(f,[1,1]);
    f=lifecycleFixture();f.log.events[1].params.source_dependency.id=44;pair(f,[3,1]);
    f=lifecycleFixture();f.log.events[2].source.start_time='1001';pair(f,[5,1]);
    f=lifecycleFixture();f.log.events.push(clone(f.log.events[1]));pair(f,[4,1]);
  });
  group('unsupported source kind cannot attribute socket counters',()=>{const f=lifecycleFixture();for(const e of f.log.events)if(e.source.id===44)e.source.type=6;const r=pair(f,[5,1]);assert.equal(r[2],0);for(const k of [7,8,9,16])assert.equal(r[k],null);});
  group('controller start range is not missing identity',()=>{const f=lifecycleFixture();for(const e of f.log.events)if(e.source.id===100)e.source.start_time='301001';const r=pair(f,[0,0]);assert.equal(r[14],null);});
  group('source missing malformed conflict and lifetime counts cleared',()=>{
    for(const [value,expected] of [[undefined,1],[null,2],['1001',3]]){const f=lifecycleFixture();if(value===undefined)delete f.log.events[2].source.start_time;else f.log.events[2].source.start_time=value;const r=pair(f,[5,1]);assert.equal(r[2],expected);for(const k of [3,7,8,9,16])assert.equal(r[k],null);}
    const f=lifecycleFixture();f.log.events.push(clone(f.log.events[7]));const r=pair(f,[4,1]);assert.equal(r[2],3);assert.equal(r[7],null);
  });
  group('duration duplicates and reversals clear controller',()=>{
    let f=lifecycleFixture();f.log.events.push(clone(f.log.events[0]));pair(f,[8,3]);
    f=lifecycleFixture();[f.log.events[0].phase,f.log.events[6].phase]=[2,1];pair(f,[8,3]);
    f=lifecycleFixture();for(let i=0;i<20;i++)f.log.events.push(f.event('TCP_CONNECT_JOB_CONNECTOR_DONE',100,6,1010+i));const r=pair(f,[0,0]);assert.equal(r[17],23);assert.equal(r[18],15);assert.equal(r[19].length,8);assert.deepEqual(r[19].map(e=>e[0]),[20,21,22,23,24,25,26,27]);
  });
  group('signed ID and code domains never wrap',()=>{
    for(const value of [-2147483648,-1,2147483647]){const f=lifecycleFixture();for(const e of f.log.events)if(e.source.id===44)e.source.id=value;assert.equal(row(f)[0],value);}
    for(const value of [0,-0,2147483648,4294967340,'44',1.5,NaN,Infinity]){const f=lifecycleFixture();f.log.events[2].source.id=value;assert.equal(run(f).value.status,2);}
    for(const value of [-0,-1,2147483648,4294967306,NaN,Infinity,'10']){const f=lifecycleFixture();f.log.events[2].source.type=value;assert.equal(pair(f,[5,1])[2],2);}
  });
  group('canonical int64 endpoints and exact relative limits',()=>{
    for(const anchor of ['9223372036854775807','-9223372036854775808']){const f=lifecycleFixture();for(const e of f.log.events){e.time=anchor;e.source.start_time=anchor;}assert.equal(row(f)[3],0);}
    for(const bad of ['+1000','01000','-0',' 1000','1e3','1.0','9223372036854775808','-9223372036854775809','100000000000000000000']){const f=lifecycleFixture();f.log.events[2].source.start_time=bad;assert.equal(pair(f,[5,1])[2],2);}
    for(const [start,expected] of [['-299000',-300000],['301000',300000],['-299001',null],['301001',null]]){const f=lifecycleFixture();for(const e of f.log.events)if(e.source.id===44)e.source.start_time=start;assert.equal(row(f)[3],expected);}
  });
  group('errors os_error cancel and target dependency are separate enums',()=>{
    const values=[undefined,0,-3,-7,-331,-9,1,'private-error',Infinity];for(const [i,value] of values.entries()){const f=lifecycleFixture();const p=f.log.events[5].params;if(value===undefined)delete p.net_error;else p.net_error=value;assert.equal(row(f)[19][1][4],i<7?i:7);}
    for(const [value,expect] of [[undefined,0],[0,1],[2,2],[-2,3],['private',4]]){const f=lifecycleFixture();if(value!==undefined)f.log.events[5].params.os_error=value;assert.equal(row(f)[19][1][5],expect);}
    const f=lifecycleFixture();f.log.events[5].params={net_error:0,cancel_reason:'private cancel',source_dependency:{id:44,type:10}};const e=row(f)[19][1];assert.equal(e[6],12);assert.equal(e[7],true);
  });
  group('ordinary getters/coercion ignored, Proxy failure unavailable',()=>{
    let calls=0;const f=lifecycleFixture();Object.defineProperty(f.log.events[2].source,'start_time',{get(){calls++;throw Error('private');}});pair(f,[5,1]);assert.equal(calls,0);
    const g=lifecycleFixture();Object.defineProperty(g.log.events[0].source,'id',{get(){calls++;throw Error('private');}});assert.equal(run(g).value.status,2);assert.equal(calls,0);
    const h=lifecycleFixture();h.log.events[0].source=new Proxy({},{getOwnPropertyDescriptor(){throw Error('private');}});assert.equal(run(h).value.status,2);
    const i=lifecycleFixture();i.log.events[0].source.toString=()=>{calls++;return 'private';};row(i);assert.equal(calls,0);
    const n=lifecycleFixture();for(const e of n.log.events)e.source=Object.assign(Object.create(null),e.source);pair(n,[0,0]);
    const inherited=lifecycleFixture();inherited.log.events[2].source=Object.create(inherited.log.events[2].source);assert.equal(run(inherited).value.status,2);
  });
  group('array holes accessors and nonplain records rejected',()=>{
    for(const mode of ['hole','get','subclass']){const f=lifecycleFixture();let calls=0;if(mode==='hole')delete f.log.events[0];if(mode==='get')Object.defineProperty(f.log.events,'0',{get(){calls++;return {};}});if(mode==='subclass')Object.setPrototypeOf(f.log.events,class extends Array{}.prototype);assert.equal(run(f).value.status,2);assert.equal(calls,0);}
  });
  group('selected constants missing aliases wrong types unavailable',()=>{
    for(const change of [f=>delete f.log.constants.logEventTypes.CONNECT_JOB,f=>f.log.constants.logEventTypes.CONNECT_JOB=f.log.constants.logEventTypes.TCP_CONNECT,f=>f.log.constants.logSourceType.SOCKET=4294967306,f=>f.log.constants.netError.ERR_ABORTED=-4,f=>f.log.constants.logEventPhase.PHASE_BEGIN=0]){const f=lifecycleFixture();change(f);assert.equal(run(f).value.status,2);}
    const f=lifecycleFixture();f.log.constants.logEventTypes.private_secret=999;f.log.events[5].params.private='private https://secret.invalid:443/token';assert.equal(run(f).value.status,0);assert(!text(run(f).value).includes('secret'));
  });
  group('pending zero, invalid references and bounded original map scans',()=>{
    const f=lifecycleFixture();f.pending.clear();const r=run(f).value;assert.equal(r.status,0);assert.equal(r.pending_keys,0);assert.deepEqual(r.records,[]);
    f.pending=new Map([['invalid',999]]);const result=run(f).value;assert.equal(result.unselected_keys,1);assert.equal(result.status,1);assert(result.flags&16);
  });
  group('fixed backing and unsafe/reused receipts omitted',()=>{
    const r=run();assert.equal(r.state.receipt.buffer.byteLength,12736);assert.equal(r.state.receipt.byteLength,8640);
    const c={synthetic:true,browser:{revision}},s=createTCPLifecycleDiagnostics();fitStartupDiagnosticBudget(c,undefined,undefined,undefined,s.receipt);fitStartupDiagnosticBudget(c,undefined,undefined,undefined,s.receipt);s.attach(c,...Object.values(lifecycleFixture()).slice(0,3));assert(!c[key]);
    for(const receipt of [new Uint32Array(2),new Uint32Array(new ArrayBuffer(12736),4,2160),new Proxy(new Uint32Array(2160),{})])assert.doesNotThrow(()=>fitStartupDiagnosticBudget({},undefined,undefined,undefined,receipt));
  });
  group('preexisting field preservation and created-only cleanup',()=>{
    const existing={private:'unchanged'},c={synthetic:true,browser:{revision},[key]:existing};const r=run(undefined,c);assert.equal(r.checks[key],existing);r.state.cleanup(c);assert.equal(c[key],existing);
    const x=run();x.state.cleanup(x.checks);assert(!x.checks[key]);const y=run();y.checks[key]=existing;y.state.cleanup(y.checks);assert.equal(y.checks[key],existing);
    const z=run(undefined,{synthetic:true,browser:{revision},startup_diagnostics:{existing:true}});assert.equal(z.value,undefined);
  });
  group('actual root bytes boundary/legacy oversize never rescued',()=>{
    const f=lifecycleFixture(),sample=run(f),increment=bytes(sample.checks)-sample.baseline;assert.equal(increment,33+JSON.stringify(sample.value,null,2).split('\n').join('\n  ').length);
    for(const room of [0,1,32,250,278,279,increment-1,increment,4095,4096,4097]){
      const c={synthetic:true,browser:{revision},padding:''};const target=262144-room;c.padding='x'.repeat(target-bytes(c));const s=createTCPLifecycleDiagnostics();fitStartupDiagnosticBudget(c,undefined,undefined,undefined,s.receipt);const before=text(c),b=bytes(c);s.attach(c,f.log,f.pending,f.names);if(c[key]){assert(bytes(c)-b<=room);assert(bytes(c)-b<=4096);delete c[key];}assert.equal(text(c),before);
    }
    const c={synthetic:true,padding:'x'.repeat(262145)},s=createTCPLifecycleDiagnostics();fitStartupDiagnosticBudget(c,undefined,undefined,undefined,s.receipt);assert.equal(s.receipt[2049],2);s.attach(c,f.log,f.pending,f.names);assert(!c[key]);assert(bytes(c)>262144);
  });
  group('earliest16 IDs, exact keys, prefix and last8 bounds',()=>{
    const f=lifecycleFixture();f.log.events=[];f.pending.clear();for(let i=0;i<20;i++){const value=i+1;f.log.events.push(f.event('SOCKET_ALIVE',value,10,1000+i*2,1,{source_dependency:{id:100,type:6}}));f.log.events.push(f.event('TCP_CONNECT',value,10,1001+i*2,1,{address:'127.0.0.1:123'}));f.pending.set('private'+i,i*2+1);}f.pending=new Map([...f.pending].reverse());f.log.events.push(f.event('CONNECT_JOB',100,6,1100,1));const r=run(f).value;assert.equal(r.selected_sources,16);assert.equal(r.pending_keys,20);assert.equal(r.unselected_keys,4);assert(r.shown_sources<16);assert.deepEqual(r.records.map(r=>r[0]),Array.from({length:r.shown_sources},(_,i)=>i+1));assert.equal(r.trimmed_keys,16-r.shown_sources);
  });
  group('old audit report and pending guard remain unchanged',()=>{
    if(!netlogAudit)return;const f=lifecycleFixture(),origins=new Set(['http://127.0.0.1:123']),endpoints=new Set(['127.0.0.1:123']);const report=netlogAudit(f.log,origins,endpoints);assert(report.violations.includes('unfinished TCP attempt; transport outcome unknown'));const before=text(report);const c={synthetic:true,browser:{revision},network_audit:report};fitTCPDiagnosticBudget(c);const state=createTCPLifecycleDiagnostics();fitStartupDiagnosticBudget(c,undefined,undefined,undefined,state.receipt);state.attach(c,f.log,f.pending,f.names);assert.equal(text(report),before);
  });
  await (await import('./test_browser_pool_owner_diagnostics.mjs')).testPoolOwnerDiagnostics({netlogAudit});
  console.log(JSON.stringify({tcp_lifecycle_diagnostics:'passed',groups:cases,scope:'pure-data/in-memory only; no Chrome/network/Go/OS pipe/CI',backing_bytes:12736,controlled_backing_plus_string_payload:20928,total_v8_heap_bound:false}));
}
