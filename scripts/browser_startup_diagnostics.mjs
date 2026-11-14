// Passive, bounded startup evidence only. No timers, I/O, control or raw text.
const MAX_COUNT=2147483647,MAX_OFFSET=300000,JSON_LIMIT=256*1024,DETAIL_LIMIT=4096;
const MARKER=Buffer.from('Remote debugging pipe file descriptors are not open.');
const ERROR_CODES=['EPIPE','ECONNRESET','ENOENT','EACCES'];
const SETTLEMENTS=['response','protocol_error','timeout','input_error','output_error','output_end','parse_error','child_error','child_exit','transport_closed'];
const ROUTES=['no_child','existing_child_error','already_exited','parent_stop','client_absent','client_closed','pending_bound'];
const own=(value,key)=>value!==null&&typeof value==='object'?Object.getOwnPropertyDescriptor(value,key)?.value:undefined;
const errorCode=value=>ERROR_CODES.includes(own(value,'code'))?own(value,'code'):'other';
const enumValue=(value,values,fallback)=>values.includes(value)?value:fallback;
const count=value=>Number.isFinite(value)&&value>=0?Math.min(MAX_COUNT,Math.floor(value)):0;
const version=value=>typeof value==='string'&&value.length<=23&&/^[0-9]{1,5}(\.[0-9]{1,5}){3}$/.test(value)?value:null;
const revision=(value,cdp=false)=>typeof value==='string'&&value.length<=(cdp?41:40)&&new RegExp(cdp?'^@?[a-fA-F0-9]{40}$':'^[a-fA-F0-9]{40}$').test(value)?value.replace(/^@/,'').toLowerCase():null;
const nodeVersion=value=>typeof value==='string'&&value.length<=18&&/^v[0-9]{1,5}(\.[0-9]{1,5}){2}$/.test(value)?value:null;
function build(value,rev) {
  return {version:version(value),version_status:value===undefined?'missing':version(value)?'valid':'invalid',
    revision:revision(rev),revision_status:rev===undefined?'missing':revision(rev)?'valid':'invalid'};
}
export function startupObserve(observer,action,...args) {
  try {return observer?.[action](...args);} catch {
    try {observer?.incomplete();} catch { /* New diagnostics alone may disappear. */ }
  }
}
export function createStderrMarkerScanner(now) {
  let total=0,scanned=0,matches=0,first=null,carry=null,failed=false,maxRetained=0;
  return {
    observe(chunk) {
      total=Math.min(MAX_COUNT,total+chunk.length);
      if(failed)return;
      try {
        let offset=0;
        while(offset<chunk.length&&scanned<65536) {
          const length=Math.min(4096,chunk.length-offset,65536-scanned);
          const window=Buffer.concat(carry?[carry,chunk.subarray(offset,offset+length)]:[chunk.subarray(offset,offset+length)]);
          let index=0;
          while((index=window.indexOf(MARKER,index))>=0) {
            matches=Math.min(MAX_COUNT,matches+1);if(first===null)first=now();index+=MARKER.length;
          }
          scanned+=length;offset+=length;
          if(scanned===65536){carry=null;break;}
          // An independent allocation cannot pin the incoming (possibly huge) Buffer.
          const keep=Math.min(MARKER.length-1,window.length);
          carry=Buffer.alloc(keep);window.copy(carry,0,window.length-keep);
          maxRetained=Math.max(maxRetained,carry.buffer.byteLength);
        }
      }catch{failed=true;carry=null;}
    },
    snapshot(){return {observed_bytes:total,scanned_bytes:scanned,scan_status:failed?'incomplete':total>65536?'limited':'complete',
      pipe_descriptors_unavailable:matches,first_marker_ms:first,saturated:total===MAX_COUNT||matches===MAX_COUNT};},
    retainedBytes(){return carry?.buffer.byteLength??0;},
    maximumRetainedBytes(){return maxRetained;}
  };
}
export function createStartupDiagnostics(node,origin,clock) {
  let incomplete=false,clipped=false,saturated=false,spawnObserved=false,spawnAt=null,childErrorStage='unobserved',childErrorCode='unobserved',childErrorAt=null;
  let exitAt=null,closeAt=null,firstByte=null,firstMessage=null,cleanupStart=null,parentStopFinished=null,route='unobserved',failure=null;
  let cdpBuild=build(),netlogBuild=build();
  const slots={get_version:null,close:null};
  const offset=()=>{
    const value=clock()-origin;
    if(!Number.isFinite(value)||value<0){incomplete=true;return null;}
    if(value>MAX_OFFSET)clipped=true;
    return Math.min(MAX_OFFSET,Math.round(value));
  };
  const scanner=createStderrMarkerScanner(offset);
  const safe=fn=>(...args)=>{try{return fn(...args);}catch{incomplete=true;}};
  const select=id=>slots.get_version?.id===id?slots.get_version:slots.close?.id===id?slots.close:null;
  const add=value=>{if(value>=MAX_COUNT)saturated=true;return Math.min(MAX_COUNT,value);};
  const metric=value=>{if(value>=MAX_COUNT)saturated=true;return count(value);};
  const state=client=>({received_bytes:metric(client?.receivedBytes),received_messages:metric(client?.receivedMessages),buffered_bytes:metric(client?.buffer?.length),
    input_writable:typeof client?.input?.writable==='boolean'?client.input.writable:null,
    input_ended:typeof client?.input?.writableEnded==='boolean'?client.input.writableEnded:null,
    input_destroyed:typeof client?.input?.destroyed==='boolean'?client.input.destroyed:null,input_queue_bytes:metric(client?.input?.writableLength),
    output_readable:typeof client?.output?.readable==='boolean'?client.output.readable:null,
    output_ended:typeof client?.output?.readableEnded==='boolean'?client.output.readableEnded:null,
    output_destroyed:typeof client?.output?.destroyed==='boolean'?client.output.destroyed:null,
    output_flowing:typeof client?.output?.readableFlowing==='boolean'?client.output.readableFlowing:null});
  const project=slot=>slot?{call_ms:slot.call_ms,deadline_ms:slot.deadline_ms,write_bytes:slot.write_bytes,write_return:slot.write_return,
    callback:slot.callback,callback_ms:slot.callback_ms,write_error:slot.write_error,settlement:slot.settlement,settled_ms:slot.settled_ms,
    late_responses:slot.late_responses,first_late_ms:slot.first_late_ms}:null;
  return {
    incomplete(){incomplete=true;},
    command:safe((method,id)=>{
      const key=method==='Browser.getVersion'?'get_version':method==='Browser.close'?'close':null;
      if(!key||slots[key])return false;
      // Sample immediately before the caller arms its unchanged timer.
      // deadline_ms is the nominal planned deadline; settled_ms is observation.
      const at=offset();if(at!==null&&at+10000>MAX_OFFSET)clipped=true;
      slots[key]={id,call_ms:at,deadline_ms:at===null?null:Math.min(MAX_OFFSET,at+10000),write_bytes:0,write_return:'unobserved',
        callback:'unobserved',callback_ms:null,write_error:'unobserved',settlement:'pending',settled_ms:null,late_responses:0,first_late_ms:null};
      return true;
    }),
    notSent:safe((method,reason)=>{if(method==='Browser.close')route=enumValue(reason,ROUTES,'unobserved');}),
    writeCallback:safe(id=>select(id)?safe(error=>{
      const slot=select(id);slot.callback=error?'error':'locally_handled';slot.callback_ms=offset();if(error)slot.write_error=errorCode(error);
    }):undefined),
    write:safe((id,length,accepted)=>{const slot=select(id);if(slot){slot.write_bytes=count(length);slot.write_return=accepted?'true':'false';}}),
    writeThrow:safe((id,error)=>{const slot=select(id);if(slot){slot.write_return='threw';slot.write_error=errorCode(error);}}),
    settle:safe((id,reason)=>{const slot=select(id);if(slot&&slot.settlement==='pending'){slot.settlement=enumValue(reason,SETTLEMENTS,'transport_closed');slot.settled_ms=offset();}}),
    data:safe(length=>{if(length>0&&firstByte===null)firstByte=offset();}),
    message:safe(message=>{
      if(firstMessage===null)firstMessage=offset();
      const id=own(message,'id'),slot=select(id);if(!slot)return;
      if(slot.settlement!=='pending'){slot.late_responses=add(slot.late_responses+1);if(slot.first_late_ms===null)slot.first_late_ms=offset();}
      if(slot===slots.get_version&&!own(message,'error')) {
        const result=own(message,'result'),product=own(result,'product'),rev=own(result,'revision');
        const value=typeof product==='string'&&product.length<=30&&product.startsWith('Chrome/')?product.slice(7):product===undefined?undefined:null;
        cdpBuild=build(value,rev===undefined?undefined:revision(rev,true)??null);
      }
    }),
    spawn:safe(()=>{spawnObserved=true;spawnAt=offset();}),
    childError:safe(error=>{childErrorStage=spawnObserved?'post_spawn':'before_spawn';childErrorCode=errorCode(error);childErrorAt=offset();}),
    exit:safe(()=>{if(exitAt===null)exitAt=offset();}),
    close:safe(()=>{if(closeAt===null)closeAt=offset();}),
    stderr:safe(chunk=>scanner.observe(chunk)),
    netlog:safe(log=>{const info=own(own(log,'constants'),'clientInfo');netlogBuild=build(own(info,'version'),own(info,'cl'));}),
    failure:safe(client=>{failure={offset_ms:offset(),...state(client)};}),
    cleanup:safe((child,existingError)=>{cleanupStart=offset();route=!child?'no_child':existingError?'existing_child_error':child.exitCode!==null||child.signalCode!==null?'already_exited':'parent_stop';}),
    parentStopped:safe(()=>{parentStopFinished=offset();}),
    snapshot:safe(client=>{const finalState=state(client),snapshotAt=offset();return {schema_version:1,status:incomplete?'incomplete':'observed',clock:'node_pre_spawn_monotonic',node:nodeVersion(node),clipped,saturated,
      spawn:{observed:spawnObserved,offset_ms:spawnAt,error_stage:childErrorStage,error_code:childErrorCode,error_ms:childErrorAt},
      get_version:project(slots.get_version),first_byte_ms:firstByte,first_parsed_message_ms:firstMessage,failure,
      cleanup:{start_ms:cleanupStart,parent_stop_finished_ms:parentStopFinished,snapshot_ms:snapshotAt,route,close:project(slots.close),exit_ms:exitAt,close_ms:closeAt,...finalState},
      chrome_build:{cdp:cdpBuild,netlog:netlogBuild,version_agreement:cdpBuild.version&&netlogBuild.version?cdpBuild.version===netlogBuild.version?'match':'mismatch':'not_comparable'},
      stderr:scanner.snapshot()};})
  };
}
const tiny=()=>({schema_version:1,status:'incomplete'});
const stateSchema={received_bytes:'count',received_messages:'count',buffered_bytes:'count',input_writable:'tri',input_ended:'tri',input_destroyed:'tri',input_queue_bytes:'count',output_readable:'tri',output_ended:'tri',output_destroyed:'tri',output_flowing:'tri'};
const slotSchema={call_ms:'offset',deadline_ms:'offset',write_bytes:'count',write_return:['unobserved','true','false','threw'],callback:['unobserved','locally_handled','error'],callback_ms:'offset',write_error:['unobserved',...ERROR_CODES,'other'],settlement:['pending',...SETTLEMENTS],settled_ms:'offset',late_responses:'count',first_late_ms:'offset'};
const buildSchema={version:'version',version_status:['missing','invalid','valid'],revision:'revision',revision_status:['missing','invalid','valid']};
const snapshotSchema={schema_version:[1],status:['incomplete','observed'],clock:['node_pre_spawn_monotonic'],node:'node',clipped:'boolean',saturated:'boolean',
  spawn:{observed:'boolean',offset_ms:'offset',error_stage:['unobserved','before_spawn','post_spawn'],error_code:['unobserved',...ERROR_CODES,'other'],error_ms:'offset'},
  get_version:slotSchema,first_byte_ms:'offset',first_parsed_message_ms:'offset',failure:{offset_ms:'offset',...stateSchema},
  cleanup:{start_ms:'offset',parent_stop_finished_ms:'offset',snapshot_ms:'offset',route:['unobserved',...ROUTES],close:slotSchema,exit_ms:'offset',close_ms:'offset',...stateSchema},
  chrome_build:{cdp:buildSchema,netlog:buildSchema,version_agreement:['match','mismatch','not_comparable']},
  stderr:{observed_bytes:'count',scanned_bytes:'count',scan_status:['incomplete','limited','complete'],pipe_descriptors_unavailable:'count',first_marker_ms:'offset',saturated:'boolean'}};
function projectSnapshot(value,schema=snapshotSchema) {
  if(Array.isArray(schema)){if(!schema.includes(value))throw new Error('invalid diagnostic enum');return value;}
  if(typeof schema==='object') {
    if(value===null)return null;
    if(!value||typeof value!=='object')throw new Error('invalid diagnostic record');
    const result={};
    // Traverse only this fixed trusted schema, never arbitrary input keys/values.
    for(const key of Object.keys(schema))result[key]=projectSnapshot(own(value,key),schema[key]);
    return result;
  }
  if(schema==='offset'&&value===null||schema==='tri'&&value===null)return null;
  if(schema==='boolean'||schema==='tri'){if(typeof value==='boolean')return value;}
  if(schema==='count'||schema==='offset'){if(Number.isInteger(value)&&value>=0&&value<=(schema==='count'?MAX_COUNT:MAX_OFFSET))return value;}
  if(schema==='version'||schema==='revision'||schema==='node') {
    const valid=schema==='version'?version:schema==='revision'?revision:nodeVersion;
    if(value===null||valid(value)===value)return value;
  }
  throw new Error('invalid diagnostic scalar');
}
export function fitStartupDiagnosticBudget(checks,observer,client,serialize=value=>JSON.stringify(value,null,2)+'\n') {
  // Caller first runs the unchanged TCP budget on checks WITHOUT this field.
  // Startup detail may never displace legacy fields or rescue legacy oversize.
  let baseline;
  try {baseline=Buffer.byteLength(serialize(checks));}catch{return;}
  if(baseline>JSON_LIMIT)return;
  const attempt=value=>{
    checks.startup_diagnostics=value;
    try {const bytes=Buffer.byteLength(serialize(checks));return bytes<=JSON_LIMIT&&bytes-baseline<=DETAIL_LIMIT;}
    finally {delete checks.startup_diagnostics;}
  };
  let full;
  try {full=projectSnapshot(startupObserve(observer,'snapshot',client));}catch{ /* Defensive outer isolation. */ }
  if(full)try{if(attempt(full)){checks.startup_diagnostics=full;return;}}catch{ /* Fall back only new diagnostics. */ }
  try{const value=tiny();if(attempt(value))checks.startup_diagnostics=value;}catch{delete checks.startup_diagnostics;}
}
