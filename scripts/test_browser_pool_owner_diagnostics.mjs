// Future natural-CI suite only. NOT executed during local candidate preparation.
import assert from 'node:assert/strict';
import {createTCPLifecycleDiagnostics,validateTCPLifecycleDiagnostics} from './browser_tcp_lifecycle_diagnostics.mjs';
import {fitStartupDiagnosticBudget} from './browser_startup_diagnostics.mjs';
import {lifecycleFixture} from './test_browser_tcp_lifecycle_diagnostics.mjs';
const KEY='tcp_lifecycle_diagnostics',CREATED='SOCKET_POOL_CONNECT_JOB_CREATED';
const revision='049750111b1e5c11565c792b2aeed5541f332bad';
const text=x=>JSON.stringify(x,null,2)+'\n',size=x=>Buffer.byteLength(text(x));
function fixture(backup=false){
  const f=lifecycleFixture();f.log.constants.logEventTypes[CREATED]=40;f.names.set(40,CREATED);
  for(const e of f.log.events)if(e.source.id===100)e.source.type=7;
  f.log.events[1].params.source_dependency.type=7;
  // Outer BEGIN -> CREATED -> inner BEGIN -> later dependency. Pending offsets
  // remain exact input indices, never reconstructed from source IDs.
  f.log.events.splice(1,0,f.event(CREATED,100,7,1000,0,{backup_job:backup}),f.event('TCP_CONNECT_JOB_CONNECT',100,7,1000,1));
  f.pending=new Map([['private outer',4],['private inner',5]]);
  return f;
}
function run(f=fixture(),{state=createTCPLifecycleDiagnostics(),room=null,revisionValue=revision}={}){
  const checks={synthetic:true,browser:{revision:revisionValue}};
  if(room!==null){
    // Measure the existing fitter's contribution on an independent plain root.
    // Never alter the real checks after its receipt is committed.
    checks.padding='界';const probe=structuredClone(checks);
    fitStartupDiagnosticBudget(probe);
    checks.padding+='x'.repeat(262144-room-size(probe));
  }
  fitStartupDiagnosticBudget(checks,undefined,undefined,undefined,state.receipt);
  const baseline=size(checks);if(room!==null)assert.equal(262144-baseline,room);
  state.attach(checks,f.log,f.pending,f.names);
  assert.equal(state.receipt.buffer.byteLength,12736);assert.equal(state.receipt.byteLength,8640);
  if(checks[KEY]){assert(size(checks)-baseline<=4096);assert(size(checks)<=262144);}
  return {checks,value:checks[KEY],state,baseline};
}
function legacy(f,opts={}){
  const previous=f.log.constants.logEventTypes[CREATED];
  delete f.log.constants.logEventTypes[CREATED];
  try {const r=run(f,opts);if(r.value?.schema_version===2){delete r.value.pool_owner;r.value.schema_version=1;}return r;}
  finally {f.log.constants.logEventTypes[CREATED]=previous;}
}
function strip(v){const r=structuredClone(v);delete r.pool_owner;r.schema_version=1;return r;}
export async function testPoolOwnerDiagnostics({netlogAudit}={}){
  let groups=0;const group=(name,fn)=>{fn();groups++;};
  group('outer BEGIN precedes CREATED, inner BEGIN and dependency follow',()=>{
    for(const [backup,state] of [[false,2],[true,3],[null,5],['false',5],[0,5]]){
      const f=fixture(backup),r=run(f),old=legacy(f);assert.deepEqual(r.value.pool_owner,[0,state]);assert.equal(r.value.schema_version,2);
      assert.equal(text(strip(r.value)),text(old.value));assert.equal(size(r.checks)-size(old.checks),44);
      assert.equal(r.value.records[0][19].length,4); // CREATED never enters old ring.
    }
  });
  group('CREATED code zero is valid but negative zero and invalid types are not',()=>{
    for(const type of [0,-0,'0',false,null,undefined,NaN,Infinity,-1,2147483648,40]){
      const f=fixture();f.log.constants.logEventTypes[CREATED]=0;
      f.names.delete(40);f.names.set(0,CREATED);f.log.events[1].type=type;
      assert.deepEqual(run(f).value.pool_owner,[0,Object.is(type,0)?2:1]);
    }
  });
  group('missing, accessor, secret properties and invalid phase are not false',()=>{
    let calls=0;const f=fixture();delete f.log.events[1].params.backup_job;
    assert.deepEqual(run(f).value.pool_owner,[0,4]);
    Object.defineProperty(f.log.events[1].params,'backup_job',{get(){calls++;throw 0;},configurable:true});
    Object.defineProperty(f.log.events[1].params,'group_id',{get(){calls++;throw 0;}});
    f.log.events[1].params.secret='https://private.invalid/token';
    assert.deepEqual(run(f).value.pool_owner,[0,5]);assert.equal(calls,0);assert(!text(run(f).value).includes('private'));
    f.log.events[1].phase=1;assert.deepEqual(run(f).value.pool_owner,[0,7]);
  });
  group('absence, duplicates, boundaries and missing outer BEGIN',()=>{
    const f=fixture();f.log.events[1].type=999;assert.deepEqual(run(f).value.pool_owner,[0,1]);
    f.log.events[1].type=40;f.log.events.push(structuredClone(f.log.events[1]));assert.deepEqual(run(f).value.pool_owner,[0,6]);
    f.log.events[10].phase=2;assert.deepEqual(run(f).value.pool_owner,[0,7]);
    const g=fixture();[g.log.events[0],g.log.events[1]]=[g.log.events[1],g.log.events[0]];assert.deepEqual(run(g).value.pool_owner,[0,7]);
    const h=fixture();h.log.events[0].type=999;assert.deepEqual(run(h).value.pool_owner,[0,0]);
  });
  group('late identity conflicts and duplicate episodes preserve legacy clearing',()=>{
    for(const change of [f=>f.log.events.push({...structuredClone(f.log.events[1]),source:{id:100,type:7,start_time:'1001'}}),f=>f.log.events.push(structuredClone(f.log.events[0])),f=>f.log.events[3].params.source_dependency.type=6]){
      const f=fixture();change(f);const r=run(f),old=legacy(f);assert.equal(text(r.value),text(old.value));assert.equal(r.value.schema_version,1);
    }
  });
  group('revision and registry transitions reset stale arena',()=>{
    for(const rev of [revision,'@'+revision,'4b3d0dabb8250b6f152d2d85d79e7706e309d087','unknown']){
      const state=createTCPLifecycleDiagnostics();state.receipt[2114]=40;state.receipt[2115]=2;
      const r=run(fixture(),{state,revisionValue:rev});assert.equal(r.value.schema_version,rev===revision||rev==='@'+revision?2:1);
    }
    const f=fixture(),r=run(f);r.state.cleanup(r.checks);
    // Reattach with the SAME unchanged root and receipt; do not refit a spent
    // receipt or manufacture fresh ownership. Header/registry values are stale.
    for(const code of [undefined,1,'40',40]){
      f.log.constants.logEventTypes[CREATED]=code;
      r.state.attach(r.checks,f.log,f.pending,f.names);
      assert.deepEqual(r.checks[KEY].pool_owner,[0,code===40?2:0]);r.state.cleanup(r.checks);
    }
    const params=f.log.events[1].params;
    f.log.events[1].params=new Proxy(params,{getOwnPropertyDescriptor(){throw 0;}});
    r.state.attach(r.checks,f.log,f.pending,f.names);assert.equal(r.checks[KEY].schema_version,1);r.state.cleanup(r.checks);
    f.log.events[1].params=params;r.state.attach(r.checks,f.log,f.pending,f.names);assert.deepEqual(r.checks[KEY].pool_owner,[0,2]);r.state.cleanup(r.checks);
    fitStartupDiagnosticBudget(r.checks,undefined,undefined,undefined,r.state.receipt);
    r.state.attach(r.checks,f.log,f.pending,f.names);assert.equal(r.checks[KEY],undefined); // spent receipt stays rejected
  });
  group('optional descriptor throws preserve complete schema1',()=>{
    for(const location of ['registry','params']){
      const f=fixture();const old=legacy(f);
      if(location==='registry')f.log.constants.logEventTypes=new Proxy(f.log.constants.logEventTypes,{getOwnPropertyDescriptor(target,key){if(key===CREATED)throw 0;return Reflect.getOwnPropertyDescriptor(target,key);}});
      else f.log.events[1].params=new Proxy(f.log.events[1].params,{getOwnPropertyDescriptor(){throw 0;}});
      assert.equal(text(run(f).value),text(old.value));
    }
  });
  group('output construction and validation throw roll back without cleanup',()=>{
    for(const location of ['define','validate']){
      const f=fixture(),old=legacy(f),define=Object.defineProperty,descriptor=Object.getOwnPropertyDescriptor;
      let hit=0,result;
      try {
        if(location==='define')Object.defineProperty=function(target,key,desc){if(key==='pool_owner'){hit++;throw 0;}return define(target,key,desc);};
        else Object.getOwnPropertyDescriptor=function(target,key){if(key==='pool_owner'){hit++;throw 0;}return descriptor(target,key);};
        result=run(f);
      }finally{Object.defineProperty=define;Object.getOwnPropertyDescriptor=descriptor;}
      assert.equal(hit,1);assert.equal(text(result.value),text(old.value));assert.equal(result.checks[KEY],result.value);
    }
  });
  group('both budget limits, Unicode baseline, exact room rollback',()=>{
    const f=fixture(),old=legacy(f),increment=size(old.checks)-old.baseline;
    for(const offset of [-1,0,1]){
      const room=increment+44+offset,r=run(f,{room}),base=legacy(f,{room});
      assert.equal(r.value.schema_version,offset<0?1:2);assert.equal(text(strip(r.value)),text(base.value));
      if(offset<0)assert.equal(text(r.checks),text(base.checks));
    }
    // All root-detail boundaries, including old-prefix trim flag changes.
    for(let count=1;count<=16;count++){
      const g=fixture();for(let i=1;i<count;i++){
        g.log.events.push(g.event('SOCKET_ALIVE',44+i,10,1008+i,1,{source_dependency:{id:100,type:7}}));
        g.pending.set('socket'+i,g.log.events.length);g.log.events.push(g.event('TCP_CONNECT',44+i,10,1009+i,1));
      }
      const r=run(g),base=legacy(g);assert.equal(text(strip(r.value)),text(base.value));
      const L=size(base.checks)-base.baseline;assert.equal(r.value.schema_version,L+44<=4096?2:1);
    }
  });
  group('closed schema1/schema2 consumer and hostile tuples',()=>{
    const valid=run().value;assert(validateTCPLifecycleDiagnostics(valid));assert(validateTCPLifecycleDiagnostics(strip(valid)));
    for(const mutation of [v=>delete v.pool_owner,v=>v.pool_owner=[1,2],v=>v.pool_owner=[0,8],v=>v.pool_owner=[-0,2],v=>v.pool_owner=[0,true],v=>v.pool_owner=[0,2,3],v=>delete v.pool_owner[0],v=>Object.defineProperty(v.pool_owner,'0',{get(){throw 0;}}),v=>v.schema_version=3,v=>v.extra=0]){
      const v=structuredClone(valid);mutation(v);assert.equal(validateTCPLifecycleDiagnostics(v),false);
    }
    for(let state=0;state<=7;state++){const v=structuredClone(valid);v.pool_owner[1]=state;assert(validateTCPLifecycleDiagnostics(v));}
  });
  group('first valid target never changes to a later positive observation',()=>{
    const f=fixture();f.log.events[0].type=999;
    f.log.events.push(f.event('CONNECT_JOB',200,7,1010,1),f.event(CREATED,200,7,1011,0,{backup_job:true}),f.event('SOCKET_ALIVE',55,10,1012,1,{source_dependency:{id:200,type:7}}));
    f.pending.set('later',f.log.events.length);f.log.events.push(f.event('TCP_CONNECT',55,10,1013,1));
    assert.deepEqual(run(f).value.pool_owner,[0,0]);
    // Two selected records sharing one controller still select only slot 0.
    const g=fixture();g.log.events.push(g.event('SOCKET_ALIVE',55,10,1012,1,{source_dependency:{id:100,type:7}}));
    g.pending.set('shared',g.log.events.length);g.log.events.push(g.event('TCP_CONNECT',55,10,1013,1));
    assert.deepEqual(run(g).value.pool_owner,[0,2]);
  });
  group('consumer slots 9,10,15 and every state remain closed',()=>{
    for(const slot of [9,10,15])for(let state=0;state<8;state++){
      const v=structuredClone(run().value),r=v.records[0];
      v.records=Array.from({length:slot+1},(_,i)=>{const row=structuredClone(r);row[0]=44+i;row[6]=i;row[12]=i===slot?6:5;return row;});
      v.selected_sources=v.shown_sources=slot+1;v.pending_keys=2*(slot+1);v.pool_owner=[slot,state];
      assert(validateTCPLifecycleDiagnostics(v));
      const base=strip(v),root=x=>JSON.stringify(x,null,2).replaceAll('\n','\n  ');
      assert.equal(Buffer.byteLength(root(v))-Buffer.byteLength(root(base)),slot<10?44:45);
      v.records[0][12]=6;assert.equal(validateTCPLifecycleDiagnostics(v),false);
    }
  });
  group('100000 entries, saturation, original last8 and no guard promotion',()=>{
    const f=fixture();while(f.log.events.length<100000)f.log.events.push(f.event(CREATED,100,7,1000,0,{backup_job:true}));
    const r=run(f),old=legacy(f);assert.deepEqual(r.value.pool_owner,[0,6]);assert.equal(text(strip(r.value)),text(old.value));
    const g=fixture();for(let i=0;i<20;i++)g.log.events.push(g.event('TCP_CONNECT_JOB_CONNECTOR_DONE',100,7,1010+i));
    const q=run(g);assert.equal(q.value.records[0][19].length,8);assert.equal(text(strip(q.value)),text(legacy(g).value));
    if(netlogAudit){const report=netlogAudit(g.log,new Set(['http://127.0.0.1:123']),new Set(['127.0.0.1:123'])),before=text(report);run(g);assert.equal(text(report),before);assert(report.violations.includes('unfinished TCP attempt; transport outcome unknown'));}
  });
  console.log(JSON.stringify({pool_owner:'passed',groups,scope:'synthetic in-memory; not cause attribution'}));
}
