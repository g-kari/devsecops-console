// Opt-in normal-runner QA only. Node 22/24 builtins; no package or browser install.
// Screenshots are actual CDP responses. Visual review remains a separate gate.
import assert from 'node:assert/strict';
import { classifyFailedUDPConnects, validNetLogSourceID, NET_SOURCE_NAMES } from './browser_udp_audit.mjs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { readFile, writeFile, mkdir, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { isIP } from 'node:net';
import { PassThrough } from 'node:stream';
import { createStartupDiagnostics, startupObserve, fitStartupDiagnosticBudget } from './browser_startup_diagnostics.mjs';
const MAX_PACKET=16*1024*1024, MAX_PNG=512*1024, IMAGE_BUDGET=7*1024*1024;
const sha256=b=>createHash('sha256').update(b).digest('hex');
const delay=ms=>new Promise(resolve=>setTimeout(resolve, ms));
function pngSize(b) {
  assert(b.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])), 'not a PNG');
  assert.equal(b.toString('ascii', 12, 16), 'IHDR');
  return {
    width:b.readUInt32BE(16), height:b.readUInt32BE(20)
  };
}
function allowedOrigin(raw, origins) {
  try {
    const u=new URL(raw);
    return u.protocol==='http:'&&!u.username&&!u.password&&u.hostname==='127.0.0.1'&&origins.has(u.origin);
  }catch {
    return false;
  }
}
function argumentsMap(args) {
  assert.equal(args.length%2, 0, 'arguments must be key/value pairs');
  const r= {};
  for(let i=0; i<args.length; i+=2) {
    assert(['--fixture', '--chrome', '--profile', '--out'].includes(args[i]), 'unknown argument');
    assert(!(args[i] in r), 'duplicate argument');
    r[args[i]]=args[i+1];
  }
  for(const key of ['--fixture', '--chrome', '--profile', '--out'])assert(r[key], `missing ${key}`);
  return r;
}
class CDP {
  constructor(input, output, startupDiagnostics) {
    this.input=input;
    this.output=output;
    this.startupDiagnostics=startupDiagnostics;
    this.buffer=Buffer.alloc(0);
    this.next=0;
    this.pending=new Map();
    this.listeners=[];
    this.closed=false;
    this.receivedBytes=0;
    this.receivedMessages=0;
    output.on('data', b=>this.accept(b));
    output.on('error', e=>this.close(e, 'output_error'));
    output.on('end', ()=>this.close(new Error('CDP pipe ended'), 'output_end'));
    input.on('error', e=>this.close(e, 'input_error'));
  }
  accept(chunk) {
    startupObserve(this.startupDiagnostics, 'data', chunk.length);
    this.receivedBytes+=chunk.length;
    try {
      this.buffer=Buffer.concat([this.buffer, chunk]);
      assert(this.buffer.length<=MAX_PACKET, 'CDP packet bound exceeded');
      let end;
      while((end=this.buffer.indexOf(0))>=0) {
        const message=JSON.parse(this.buffer.subarray(0, end).toString('utf8'));
        this.receivedMessages++;
        startupObserve(this.startupDiagnostics, 'message', message);
        this.buffer=this.buffer.subarray(end+1);
        if(Number.isInteger(message.id)) {
          const p=this.pending.get(message.id);
          if(p) {
            clearTimeout(p.timer);
            this.pending.delete(message.id);
            startupObserve(this.startupDiagnostics, 'settle', message.id, message.error?'protocol_error':'response');
            message.error?p.reject(new Error(`CDP ${p.method}: ${JSON.stringify(message.error)}`)):p.resolve(message.result?? {});
          }
        }else {
          for(const listener of this.listeners)listener(message);
        }
      }
    }catch(e) {
      this.close(e, 'parse_error');
    }
  }
  call(method, params= {}, sessionId) {
    if(this.closed){startupObserve(this.startupDiagnostics, 'notSent', method, 'client_closed');return Promise.reject(new Error('CDP is closed'));}
    if(this.pending.size>=64){startupObserve(this.startupDiagnostics, 'notSent', method, 'pending_bound');return Promise.reject(new Error('CDP pending-command bound exceeded'));}
    const id=++this.next;
    return new Promise((resolve, reject)=> {
      startupObserve(this.startupDiagnostics, 'command', method, id);
      const timer=setTimeout(()=> {
        this.pending.delete(id);
        startupObserve(this.startupDiagnostics, 'settle', id, 'timeout');
        reject(new Error(`CDP timeout: ${method}`));
      }, 10000);
      this.pending.set(id, {
        resolve, reject, timer, method
      });
      const frame=JSON.stringify( {
        id, method, params, ...(sessionId? {
          sessionId
        }
        : {})
      })+'\0';
      const callback=startupObserve(this.startupDiagnostics, 'writeCallback', id);
      try {
        const accepted=callback?this.input.write(frame, callback):this.input.write(frame);
        startupObserve(this.startupDiagnostics, 'write', id, Buffer.byteLength(frame), accepted);
      }catch(e) {
        startupObserve(this.startupDiagnostics, 'writeThrow', id, e);
        throw e;
      }
    });
  }
  close(error, reason='transport_closed') {
    if(this.closed)return;
    this.closed=true;
    for(const [id,p] of this.pending) {
      clearTimeout(p.timer);
      startupObserve(this.startupDiagnostics, 'settle', id, reason);
      p.reject(error);
    }
    this.pending.clear();
  }
}
// Track only CDP interception decisions, never the lifetime of an SSE response.
// Drain settles decisions already observed (including arrivals while draining).
// Only a stale ID for an already-safe GET/HEAD request is a benign cancellation;
// every other decision error stays fatal.
function isBenignSafeFetchCancellation(error, metadata) {
  const prefix='CDP Fetch.continueRequest: ';
  const message=String(error?.message??error);
  if(!message.startsWith(prefix))return false;
  let details;
  try {
    details=JSON.parse(message.slice(prefix.length));
  }catch {
    return false;
  }
  return metadata?.safe===true&&metadata.fixture_origin===true&&['GET','HEAD'].includes(metadata.method)
    &&metadata.response_stage===false&&details?.code===-32602&&details?.message==='Invalid InterceptionId.';
}
function isFetchResponseStage(params) {
  if(!params||typeof params!=='object')return false;
  return ['responseStatusCode','responseStatusText','responseHeaders','responseErrorReason'].some(key=>Object.hasOwn(params,key));
}
class FetchDecisions {
  constructor(onError,onBenignCancellation=()=>{}) {
    this.pending=new Set();
    this.onError=onError;
    this.onBenignCancellation=onBenignCancellation;
  }
  track(operation, metadata) {
    const pending=Promise.resolve().then(operation).catch(error=>{
      if(isBenignSafeFetchCancellation(error,metadata)) {
        this.onBenignCancellation(metadata);
        return;
      }
      this.onError(error,metadata);
    }).finally(()=>this.pending.delete(pending));
    this.pending.add(pending);
  }
  async drain(timeout=10000) {
    let timer;
    const expired=new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Fetch decision drain deadline exceeded')),timeout);});
    try {
      await Promise.race([(async()=>{
        while(this.pending.size)await Promise.all([...this.pending]);
      })(),expired]);
    }finally {
      clearTimeout(timer);
    }
  }
}
function rgb(text) {
  let m=text.match(/^rgba?\(([^)]+)\)$/);
  if(m) {
    const parts=m[1].split(/[, /]+/).filter(Boolean).map(Number);
    assert(parts.length>=3&&parts.slice(0, 3).every(Number.isFinite), 'unsupported RGB');
    assert(parts.length<4||parts[3]===1, 'transparent contrast surface');
    return parts.slice(0, 3).map(v=>v/255);
  }
  m=text.match(/^color\(srgb ([\d.]+) ([\d.]+) ([\d.]+)\)$/);
  assert(m, `unsupported computed color ${text}`);
  return m.slice(1).map(Number);
}
function contrast(fg, bg) {
  const lum=s=>rgb(s).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((n, v, i)=>n+v*[.2126, .7152, .0722][i], 0);
  const a=lum(fg), b=lum(bg);
  return (Math.max(a, b)+.05)/(Math.min(a, b)+.05);
}
// No query, fragment, credentials or raw CONNECT authority is persisted.
function networkLabel(raw) {
  try {
    const u=new URL(raw);
    return `${u.protocol}//${u.hostname}${u.port?':'+u.port:''}${u.pathname}`.slice(0, 256);
  } catch {
    return '[unparseable network target]';
  }
}
function scrubNetworkText(text) {
  return String(text).replace(/(?:https?|wss?):\/\/[^\s\"'<>]+/g, networkLabel);
}
// Navigation diagnostics contain no headers, bodies, query strings or CDP IDs.
// Keep the most recent events, including the last failed navigation, bounded.
function navigationDiagnostic(events, kind, details={}) {
  const entry={kind};
  if(typeof details.url==='string')entry.url=networkLabel(details.url);
  if(Number.isInteger(details.status))entry.status=details.status;
  if(typeof details.error==='string')entry.error=scrubNetworkText(details.error).slice(0,512);
  if(typeof details.type==='string')entry.type=details.type.slice(0,64);
  if(typeof details.waiting==='boolean')entry.waiting=details.waiting;
  if(events.length===64)events.shift();
  events.push(entry);
}
function networkPolicy(origins, proxyOrigin) {
  assert(origins.size===3);
  for(const u of origins)assert(allowedOrigin(u, origins)&&new URL(u).pathname==='/');
  assert(allowedOrigin(proxyOrigin, new Set([proxyOrigin]))&&!origins.has(proxyOrigin));
  return {
    // Chrome's mapped resolver applies MAP to numeric literals too. EXCLUDE
    // prevents our own fixture/proxy IP from being rewritten to NOTFOUND.
    // Chrome 156's mapped resolver recognizes ^NOTFOUND, not ~NOTFOUND:
    // https://github.com/chromium/chromium/blob/a21ce95c24ce3964416f09ae1862f53f319eb4d0/net/dns/mapped_host_resolver.cc#L64-L80
    // The excluded loopback resolver may still probe IPv6; the UDP gate stays strict.
    resolver:'MAP * ^NOTFOUND, EXCLUDE 127.0.0.1',
    // Remove Chromium's implicit broad loopback bypass, then allow ONLY the
    // exact fixture scheme/host/port. Everything else reaches a deny-only proxy.
    bypass:['<-loopback>', ...origins].join(';'),
    endpoints:new Set([...origins, proxyOrigin].map(u=>new URL(u).host))
  };
}
function internalTarget(info) {
  return ['browser_ui', 'background_page', 'service_worker'].includes(info.type)&& (info.url===''||info.url==='about:blank'||/^(chrome|chrome-untrusted|chrome-extension|devtools):\/\//.test(info.url));
}
const CODEX_READY="(()=>{const n=document.querySelector('#codex-auth-status');return !!n&&n.textContent.includes('Synthetic offline browser QA; no CLI invoked')})()";
const UDP_DETAIL_LIMITS=Object.freeze({sources:64,events:256,edges:128,depth:8,bytes:64*1024});
const UDP_TYPES=new Set(['UDP_SOCKET','UDP_CLIENT_SOCKET']);
const UDP_EVENTS=new Set(['UDP_CONNECT','UDP_LOCAL_ADDRESS','UDP_BYTES_SENT','UDP_BYTES_RECEIVED','UDP_SEND_ERROR','UDP_RECEIVE_ERROR']);
const UDP_CONTEXT_EVENTS=new Set(['SOCKET_ALIVE','SOCKET_OPEN','SOCKET_CONNECT','HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK']);
function literalEndpoint(raw) {
  if(typeof raw!=='string'||raw.length>128)return null;
  const match=raw.startsWith('[')?raw.match(/^\[([0-9a-fA-F:.]+)\]:([0-9]{1,5})$/):raw.match(/^([0-9.]+):([0-9]{1,5})$/);
  if(!match||match[0]!==raw)return null;
  const family=isIP(match[1]),port=Number(match[2]);
  if(!family||!Number.isInteger(port)||port>65535||(family===6)!==raw.startsWith('['))return null;
  const host=family===6?new URL(`http://[${match[1]}]/`).hostname:match[1];
  const bare=host.replace(/^\[|\]$/g,'');
  const loopback=family===4?/^127\./.test(bare):bare==='::1';
  const first=family===6?Number.parseInt(bare.split(':')[0],16):0;
  const linkLocal=family===4?/^169\.254\./.test(bare):first>=0xfe80&&first<=0xfebf;
  return {endpoint:`${host}:${port}`,family,scope:loopback?'loopback':linkLocal?'link_local':'non_loopback'};
}
// Bounded diagnostic projection. Any failed-operation classification also
// validates the original raw event sequence and metadata separately.
// No raw params/URLs/payload bytes/local IPs enter this bounded projection.
function udpNetlogDetails(log) {
  const limits=UDP_DETAIL_LIMITS,reasons=new Map(),sources=new Map(),allEdges=new Map(),seeds=new Set();
  const types=new Map(Object.entries(log.constants?.logEventTypes??{}).map(([k,v])=>[v,k]));
  const sourceTypes=new Map(Object.entries(log.constants?.logSourceType??{}).map(([k,v])=>[v,k]));
  const phaseTypes=new Map(Object.entries(log.constants?.logEventPhase??{}).map(([k,v])=>[v,k]));
  const errors=new Set(Object.values(log.constants?.netError??{}));
  const fail=reason=>reasons.set(reason,(reasons.get(reason)??0)+1);
  const sourceName=value=>NET_SOURCE_NAMES.has(sourceTypes.get(value))?sourceTypes.get(value):'UNKNOWN_SOURCE_TYPE';
  const validID=validNetLogSourceID;
  const dnsEvent=name=>typeof name==='string'&&(/^(DNS_TRANSACTION|MDNS_)/.test(name));
  const knownName=name=>UDP_EVENTS.has(name)||UDP_CONTEXT_EVENTS.has(name);
  let observedUDP=0,observedSends=0,observedSendErrors=0;
  function source(raw,seen) {
    if(!validID(raw?.id)||!Number.isSafeInteger(raw?.type)){return null;}
    let node=sources.get(raw.id);
    if(!node){node={id:raw.id,type:raw.type,seen:false,conflict:false};sources.set(raw.id,node);}
    if(node.type!==raw.type)node.conflict=true;
    node.seen||=seen;
    return node;
  }
  // Bounded input (16MiB/100000 events) was checked by the caller. Build only
  // identity/dependency indexes, not copies of arbitrary event parameters.
  for(const event of log.events) {
    const name=types.get(event.type),node=source(event.source,true);
    const udp=typeof name==='string'&&name.startsWith('UDP_');
    if(udp){observedUDP++;if(node)seeds.add(node.id);else fail('udp_source_identity_missing');}
    if(name==='UDP_BYTES_SENT'){observedSends++;fail('udp_send_event_including_zero_bytes');}
    if(name==='UDP_SEND_ERROR')observedSendErrors++;
    if(node&&UDP_TYPES.has(sourceName(node.type)))seeds.add(node.id);
    const raw=event.params?.source_dependency;
    if(raw!==undefined&&node) {
      const dependency=source(raw,false);
      if(dependency)allEdges.set(`${node.id}:${dependency.id}`,{from:node.id,to:dependency.id});
      else if(udp||UDP_TYPES.has(sourceName(node.type)))fail('dependency_identity_missing');
    }
  }
  const result={scope:'captured Chromium NetLog source chains only; not OS packet capture',probe_attribution:'unknown; endpoint/marker alone do not establish a call site',limitations:['AddressSorter can use a non-capturing null NetLog; absence of events is not global zero-egress proof'],limits,observed_udp_events:observedUDP,observed_send_events:observedSends,observed_send_errors:observedSendErrors,has_send_event:observedSends>0,has_send_attempt:observedSends+observedSendErrors>0,details_complete:false,sources:[],dependencies:[],events:[],components:[],failure_reasons:[],overflow:false};
  if(!seeds.size&&!observedUDP){result.details_complete=true;return result;}
  if(!Number.isInteger(log.constants?.logEventPhase?.PHASE_NONE)||!errors.size)fail('diagnostic_constants_missing');
  // Project every UDP source and its immediate ownership/anomaly endpoints.
  // A non-UDP parent can share TCP sockets with arbitrarily many HTTP jobs;
  // those siblings are outside this diagnostic projection, not exempt from
  // the classifier's complete raw identity/dependency/UDP/DNS validation.
  result.projection_scope='all UDP sources and immediate dependency endpoints; stop at non-UDP context';
  result.raw_graph_validation='classification separately validates all raw identities and dependencies';
  const selected=new Set();
  function select(id,depth=0) {
    if(selected.has(id))return;
    if(depth>limits.depth){result.overflow=true;fail('dependency_depth_exceeded');return;}
    if(selected.size>=limits.sources){result.overflow=true;fail('source_bound_exceeded');return;}
    selected.add(id);
  }
  for(const id of seeds)select(id);
  for(const edge of allEdges.values())if(seeds.has(edge.from)||seeds.has(edge.to)) {
    select(edge.from,seeds.has(edge.from)?0:1);select(edge.to,seeds.has(edge.to)?0:1);
  }
  result.context_boundary_edges=[...allEdges.values()].filter(edge=>selected.has(edge.from)!==selected.has(edge.to)).length;
  for(const edge of allEdges.values())if(selected.has(edge.from)&&selected.has(edge.to)) {
    if(result.dependencies.length<limits.edges)result.dependencies.push(edge);
    else {result.overflow=true;fail('dependency_edge_bound_exceeded');}
  }
  const adjacent=new Map();
  for(const edge of result.dependencies)for(const [a,b]of [[edge.from,edge.to],[edge.to,edge.from]]){
    if(!adjacent.has(a))adjacent.set(a,new Set());adjacent.get(a).add(b);
  }
  const states=new Map(),connects=new Map(),connectedDestinations=new Map(),alive=new Map();
  for(const id of selected) {
    const node=sources.get(id),type=sourceName(node?.type);
    if(!node||!node.seen)fail('dependency_source_event_missing');
    if(node?.conflict)fail('source_type_conflict');
    if(type==='UNKNOWN_SOURCE_TYPE')fail('source_type_unknown');
    const row={id,type,type_value:node?.type??null,seen_event_source:node?.seen??false,connect_operations:0,send_events:0,send_attempt_errors:0,has_send_event:false,has_send_attempt:false,socket_lifetime:UDP_TYPES.has(type)?{begin_index:null,end_index:null,complete:false}:null};
    result.sources.push(row);states.set(id,row);
  }
  function endpoint(params,row,key) {
    const parsed=literalEndpoint(params.address);
    if(!parsed){fail('endpoint_not_literal_ip_port');row.endpoint_status='unknown';return;}
    if(key==='local')row.local_address={family:parsed.family,scope:parsed.scope};
    else row.destination=parsed;
  }
  function errorResult(params,row,successOmission) {
    if(params.net_error===undefined&&successOmission){row.net_error=0;row.result_basis='verified_schema_omission';return;}
    if(!Number.isSafeInteger(params.net_error)||params.net_error>0||!errors.has(params.net_error)) {
      fail('net_error_unknown');row.result_basis='unknown';return;
    }
    row.net_error=params.net_error;row.result_basis='recorded_net_error';
  }
  for(let index=0;index<log.events.length;index++) {
    const event=log.events[index],id=event.source?.id;
    if(!selected.has(id))continue;
    const name=types.get(event.type),node=states.get(id),udpSocket=UDP_TYPES.has(node.type),udpName=typeof name==='string'&&name.startsWith('UDP_');
    if(!knownName(name)&&!dnsEvent(name)&&!udpName)continue;
    if(!udpSocket&&!udpName&&!dnsEvent(name)&&name!=='HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK')continue;
    const phase=phaseTypes.get(event.phase),params=event.params??{};
    const row={event_index:index,source_id:id,event_type:knownName(name)?name:dnsEvent(name)?'DNS_OR_MDNS_EVENT':'UNKNOWN_UDP_EVENT',event_type_value:Number.isSafeInteger(event.type)?event.type:null,phase:['PHASE_BEGIN','PHASE_END','PHASE_NONE'].includes(phase)?phase:'UNKNOWN_PHASE'};
    if(row.phase==='UNKNOWN_PHASE')fail('event_phase_unknown');
    if(udpName&&!UDP_EVENTS.has(name))fail('udp_event_unknown');
    if(udpName&&!udpSocket)fail('udp_event_source_type_unexpected');
    if(dnsEvent(name))fail('dns_or_mdns_event');
    if(name==='UDP_CONNECT') {
      if(phase==='PHASE_BEGIN') {
        endpoint(params,row,'remote');
        connectedDestinations.delete(id);
        if(connects.has(id))fail('duplicate_connect_begin');
        connects.set(id,{index,destination:row.destination?.endpoint??null});node.connect_operations++;
      } else if(phase==='PHASE_END') {
        const begin=connects.get(id);
        if(!begin)fail('unpaired_connect_end');
        else {row.begin_index=begin.index;row.matched_destination=begin.destination;connects.delete(id);}
        errorResult(params,row,!!begin);
        if(row.net_error===0&&begin?.destination)connectedDestinations.set(id,begin.destination);
      } else fail('connect_phase_invalid');
    }
    if(name==='SOCKET_CONNECT') {endpoint(params,row,'remote');errorResult(params,row,true);if(phase!=='PHASE_NONE')fail('socket_connect_phase_invalid');}
    if(name==='SOCKET_OPEN') {errorResult(params,row,true);if(phase!=='PHASE_NONE')fail('socket_open_phase_invalid');}
    if(name==='SOCKET_ALIVE') {
      if(phase==='PHASE_BEGIN') {
        if(alive.has(id))fail('duplicate_socket_lifetime_begin');
        alive.set(id,index);node.socket_lifetime.begin_index=index;
        if(params.source_dependency===undefined)fail('socket_dependency_missing');
      } else if(phase==='PHASE_END') {
        if(!alive.has(id))fail('unpaired_socket_lifetime_end');
        else {node.socket_lifetime.complete=true;alive.delete(id);}
        node.socket_lifetime.end_index=index;
      } else fail('socket_lifetime_phase_invalid');
    }
    if(name==='UDP_LOCAL_ADDRESS')endpoint(params,row,'local');
    if(name==='UDP_BYTES_SENT'||name==='UDP_BYTES_RECEIVED') {
      if(!Number.isSafeInteger(params.byte_count)||params.byte_count<0||params.byte_count>65535)fail('datagram_byte_count_unknown');
      else row.byte_count=params.byte_count;
      if(params.address!==undefined)endpoint(params,row,'remote');
      else if(connectedDestinations.has(id))row.connected_destination=connectedDestinations.get(id);
      else {row.destination_status='unknown';fail('datagram_destination_unknown');}
      if(name==='UDP_BYTES_SENT'){node.send_events++;node.has_send_event=true;node.has_send_attempt=true;}
      else fail('unexpected_udp_receive');
    }
    if(name==='UDP_SEND_ERROR'||name==='UDP_RECEIVE_ERROR') {
      errorResult(params,row,false);
      if(name==='UDP_SEND_ERROR'){node.send_attempt_errors++;node.has_send_attempt=true;}
      fail(name==='UDP_SEND_ERROR'?'udp_send_attempt_error':'unexpected_udp_receive_error');
    }
    if(name==='HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK')for(const key of ['ipv6_available','cached']) {
      if(typeof params[key]==='boolean')row[key]=params[key];else fail('reachability_marker_incomplete');
    }
    if(params.source_dependency!==undefined) {
      const dependency=params.source_dependency;
      if(validID(dependency?.id)&&sources.get(dependency.id)?.type===dependency?.type)row.dependency_source_id=dependency.id;
      else fail('dependency_identity_missing');
    }
    if(result.events.length<limits.events)result.events.push(row);
    else {result.overflow=true;fail('event_detail_bound_exceeded');}
  }
  for(const id of connects.keys())fail('connect_end_missing');
  for(const row of result.sources)if(UDP_TYPES.has(row.type)&&(!row.socket_lifetime.complete||alive.has(row.id)))fail('socket_lifetime_incomplete');
  const grouped=new Set();
  for(const id of selected)if(!grouped.has(id)) {
    const ids=[],pending=[id];grouped.add(id);
    for(let i=0;i<pending.length;i++)for(const next of adjacent.get(pending[i])??[])if(selected.has(next)&&!grouped.has(next)){grouped.add(next);pending.push(next);}
    ids.push(...pending);
    result.components.push({source_ids:ids,udp_source_ids:ids.filter(x=>UDP_TYPES.has(states.get(x).type)),has_send_event:ids.some(x=>states.get(x).has_send_event),has_send_attempt:ids.some(x=>states.get(x).has_send_attempt),send_events:ids.reduce((n,x)=>n+states.get(x).send_events,0),send_attempt_errors:ids.reduce((n,x)=>n+states.get(x).send_attempt_errors,0)});
  }
  result.failure_reasons=[...reasons].map(([reason,count])=>({reason,count}));
  result.details_complete=!result.overflow&&!result.failure_reasons.length;
  if(Buffer.byteLength(JSON.stringify(result))>limits.bytes) {
    return {scope:result.scope,probe_attribution:result.probe_attribution,limitations:result.limitations,limits,observed_udp_events:observedUDP,observed_send_events:observedSends,observed_send_errors:observedSendErrors,has_send_event:observedSends>0,has_send_attempt:observedSends+observedSendErrors>0,details_complete:false,overflow:true,sources:[],dependencies:[],events:[],components:[],failure_reasons:[{reason:'diagnostic_byte_bound_exceeded',count:1}]};
  }
  return result;
}
// Observations only: never use this projection to accept or reject transport.
const TCP_DETAIL_LIMITS=Object.freeze({pending_records:16,same_id_events_per_record:4,bytes:16384,relative_time_ms:300000});
const TCP_DETAIL_SCOPE='pending keys from the existing TCP audit; not packet capture';
const TCP_DETAIL_REASONS=['identity_invalid','relative_time_unknown','pending_record_limit','same_id_event_limit','diagnostic_byte_bound','artifact_byte_bound','projection_unavailable'];
function tcpDiagnosticSummary(count,status,reasons=[]) {
  return {schema_version:1,scope:TCP_DETAIL_SCOPE,matching_basis:'source_id_event_name_latest_begin',limits:TCP_DETAIL_LIMITS,
    unfinished_key_count:count,recorded_key_count:0,omitted_key_count:count,projection_status:status,reason_counts:reasons,records:[]};
}
function tcpDiagnosticBytes(diagnostic) {
  // Include the actual checks.network_audit indentation and final newline.
  // The small wrapper overhead makes this a conservative persisted-byte bound.
  return Buffer.byteLength(JSON.stringify({network_audit:{tcp_diagnostics:diagnostic}},null,2)+'\n');
}
function tcpNetlogDetails(log,unfinished,endpoints,names) {
  const count=unfinished.size;
  try {
    const reasons=new Map(),reason=(name,n=1)=>reasons.set(name,(reasons.get(name)??0)+n);
    const result=tcpDiagnosticSummary(count,'complete');
    // Reuse the audit's inverse Map read-only; never rebuild a constants index.
    const phaseConstants=log.constants?.logEventPhase??{};
    const ticks=value=>{
      if(typeof value!=='string'||!/^-?(0|[1-9][0-9]{0,18})$/.test(value)||value==='-0')return null;
      const n=BigInt(value);
      return n>=-9223372036854775808n&&n<=9223372036854775807n?n:null;
    };
    const anchor=ticks(log.events[0]?.time);
    const relative=index=>{
      const value=ticks(log.events[index]?.time),delta=anchor!==null&&value!==null?value-anchor:null;
      if(delta===null||delta<0n||delta>BigInt(TCP_DETAIL_LIMITS.relative_time_ms)){reason('relative_time_unknown');return null;}
      return Number(delta);
    };
    const eventName=event=>{
      const name=names.get(event.type);
      return ['TCP_CONNECT','TCP_CONNECT_ATTEMPT','SOCKET_BYTES_SENT','SOCKET_ALIVE'].includes(name)?name:'OTHER';
    };
    const phase=event=>{
      const matches=['PHASE_BEGIN','PHASE_END','PHASE_NONE'].filter(name=>Number.isSafeInteger(phaseConstants[name])&&event.phase===phaseConstants[name]);
      return matches.length===1?matches[0]:'UNKNOWN';
    };
    // Select only a fixed-length set of the earliest surviving BEGIN indexes.
    // Map keys retain the old guard's exact matching semantics and stay private.
    const selected=[];
    for(const index of unfinished.values()) {
      if(!Number.isSafeInteger(index)||index<0||index>=log.events.length)throw new Error('invalid private BEGIN index');
      if(selected.length<TCP_DETAIL_LIMITS.pending_records||index<selected.at(-1)) {
        selected.push(index);selected.sort((a,b)=>a-b);
        if(selected.length>TCP_DETAIL_LIMITS.pending_records)selected.pop();
      }
    }
    if(count>selected.length)reason('pending_record_limit',count-selected.length);
    const contexts=new Map();
    for(const index of selected) {
      const event=log.events[index],id=event.source?.id,name=eventName(event);
      if(!['TCP_CONNECT','TCP_CONNECT_ATTEMPT'].includes(name))throw new Error('invalid private BEGIN event');
      const valid=validNetLogSourceID(id),counts={total:0,allowlisted:0,non_allowlisted:0,non_string:0};
      const observe=value=>{
        counts.total++;
        if(typeof value!=='string')counts.non_string++;
        else if(endpoints.has(value))counts.allowlisted++;
        else counts.non_allowlisted++;
      };
      const params=event.params??{};
      if(Array.isArray(params.address_list))for(const address of params.address_list)observe(address);
      for(const key of ['address','remote_address','peer_address'])if(params[key]!==undefined)observe(params[key]);
      if(valid&&!contexts.has(id))contexts.set(id,{count:0,indexes:[]});
      if(!valid)reason('identity_invalid');
      result.records.push({source_id:valid?id:null,identity_status:valid?'valid':'invalid',event_type:name,begin_index:index,
        relative_time_ms:relative(index),begin_endpoint_counts:counts,same_id_event_count:valid?0:null,
        omitted_same_id_event_count:valid?0:null,recent_same_id_events:[]});
    }
    // Same numeric ID is merely a captured identity, not ownership attribution.
    // Retain indexes rather than raw events or arbitrary parameter objects.
    for(let index=0;index<log.events.length;index++) {
      const context=contexts.get(log.events[index].source?.id);
      if(!context)continue;
      context.count++;context.indexes.push(index);
      if(context.indexes.length>TCP_DETAIL_LIMITS.same_id_events_per_record)context.indexes.shift();
    }
    for(const row of result.records) {
      if(row.identity_status!=='valid')continue;
      const context=contexts.get(row.source_id);
      row.same_id_event_count=context.count;
      row.omitted_same_id_event_count=context.count-context.indexes.length;
      if(row.omitted_same_id_event_count)reason('same_id_event_limit',row.omitted_same_id_event_count);
      row.recent_same_id_events=context.indexes.map(index=>({event_index:index,event_type:eventName(log.events[index]),phase:phase(log.events[index]),relative_time_ms:relative(index)}));
    }
    const finish=()=>{
      result.recorded_key_count=result.records.length;result.omitted_key_count=count-result.records.length;
      result.reason_counts=TCP_DETAIL_REASONS.filter(name=>reasons.has(name)).map(name=>({reason:name,count:reasons.get(name)}));
      result.projection_status=count&&!result.records.length?'summary_only':result.reason_counts.length?'partial':'complete';
    };
    finish();
    while(tcpDiagnosticBytes(result)>TCP_DETAIL_LIMITS.bytes&&result.records.length) {
      result.records.pop();reason('diagnostic_byte_bound');finish();
    }
    return result;
  }catch {
    // Do not turn a diagnostic failure into transport success or echo an error.
    return tcpDiagnosticSummary(count,'unavailable',[{reason:'projection_unavailable',count:1}]);
  }
}
function fitTCPDiagnosticBudget(checks) {
  const report=checks.network_audit;
  if(!report||!Object.hasOwn(report,'tcp_diagnostics'))return;
  const fits=()=>Buffer.byteLength(JSON.stringify(checks,null,2)+'\n')<=256*1024;
  if(fits())return;
  const diagnostic=report.tcp_diagnostics;
  report.tcp_diagnostics=tcpDiagnosticSummary(diagnostic.unfinished_key_count,'summary_only',[
    ...diagnostic.reason_counts.filter(row=>TCP_DETAIL_REASONS.includes(row.reason)&&row.reason!=='artifact_byte_bound').map(row=>({reason:row.reason,count:row.count})),
    {reason:'artifact_byte_bound',count:1}
  ]);
  // The original evidence and its size assertion always take precedence.
  if(!fits())delete report.tcp_diagnostics;
}
function netlogAudit(log, origins, endpoints) {
  assert(log&&Array.isArray(log.events)&&log.events.length<=100000, 'invalid/bounded NetLog events');
  const types=log.constants?.logEventTypes, phases=log.constants?.logEventPhase;
  for(const name of ['TCP_CONNECT', 'TCP_CONNECT_ATTEMPT', 'SOCKET_BYTES_SENT', 'UDP_CONNECT', 'UDP_BYTES_SENT'])assert(Number.isInteger(types?.[name]), `missing NetLog constant ${name}`);
  assert(Number.isInteger(phases?.PHASE_BEGIN)&&Number.isInteger(phases?.PHASE_END), 'missing NetLog phases');
  const names=new Map(Object.entries(types).map(([k, v])=>[v, k])), sockets=new Set(), attempts=new Map();
  const udpDetails=udpNetlogDetails(log), failedUDP=classifyFailedUDPConnects(log,udpDetails);
  const report= {
    failed_udp_connect_operations:failedUDP.operations, failed_udp_classification_reasons:failedUDP.reasons, failed_udp_classification_diagnostic:failedUDP.diagnostic??null,
    socket_pool_stalls:0, url_attempt_count:0, non_fixture_url_attempt_count:0, non_fixture_url_attempts:[], tcp_endpoint_events:0, tcp_bytes_sent_events:0, udp_events:0, violations:[], scope:'Chromium NetLog socket events; not OS packet capture', url_attempts_are_not_transport_success:true
  };
  const bad=x=> {
    if(report.violations.length<16)report.violations.push(x);
  };
  function visit(v) {
    if(!v||typeof v!=='object')return;
    for(const [key, value] of Object.entries(v)) {
      if(typeof value==='string'&&/url/i.test(key)&&/^(https?|wss?):/i.test(value)) {
        report.url_attempt_count++;
        if(!allowedOrigin(value, origins)) {
          report.non_fixture_url_attempt_count++;
          const label=networkLabel(value);
          if(report.non_fixture_url_attempts.length<16&&!report.non_fixture_url_attempts.includes(label))report.non_fixture_url_attempts.push(label);
        }
      }else if(value&&typeof value==='object')visit(value);
    }
  }
  for(const [eventIndex,event] of log.events.entries()) {
    visit(event.params);
    const name=names.get(event.type), params=event.params?? {}, id=event.source?.id;
    if(name==='SOCKET_POOL_STALLED_MAX_SOCKETS_PER_GROUP'||name==='SOCKET_POOL_STALLED_MAX_SOCKETS')report.socket_pool_stalls++;
    if(['TCP_CONNECT', 'TCP_CONNECT_ATTEMPT', 'SOCKET_BYTES_SENT', 'UDP_CONNECT', 'UDP_BYTES_SENT'].includes(name)&&!Number.isInteger(id))bad('transport event source identity missing');
    if(name==='UDP_CONNECT'||name==='UDP_BYTES_SENT'||name?.startsWith('DNS_TRANSACTION')) {
      report.udp_events++;
      if(name!=='UDP_CONNECT'||!failedUDP.eventIndexes.has(eventIndex))bad(`unexpected ${name}; no UDP/DNS transport permitted`);
    }
    if(name==='TCP_CONNECT'||name==='TCP_CONNECT_ATTEMPT') {
      const addresses=[];
      if(Array.isArray(params.address_list))addresses.push(...params.address_list);
      for(const key of ['address', 'remote_address', 'peer_address'])if(params[key]!==undefined)addresses.push(params[key]);
      for(const address of addresses) {
        report.tcp_endpoint_events++;
        if(typeof address!=='string'||!endpoints.has(address))bad('non-allowlisted TCP endpoint observed');
        else sockets.add(id);
      }
      if(event.phase===phases.PHASE_BEGIN) {
        if(addresses.length===0)bad(`missing ${name} endpoint; transport outcome unknown`);
        attempts.set(`${id}:${name}`, eventIndex);
      }
      if(event.phase===phases.PHASE_END) {
        if(!attempts.delete(`${id}:${name}`))bad(`unpaired ${name}; transport audit incomplete`);
      }
    }
    if(name==='SOCKET_BYTES_SENT') {
      report.tcp_bytes_sent_events++;
      if(!sockets.has(id))bad('socket bytes sent without allowlisted TCP endpoint evidence');
    }
  }
  if(attempts.size)bad('unfinished TCP attempt; transport outcome unknown');
  if(report.tcp_endpoint_events===0||report.tcp_bytes_sent_events===0)bad('no actual loopback socket traffic evidence');
  report.udp_diagnostics=udpDetails;
  for(const {reason}of report.udp_diagnostics.failure_reasons)bad(`UDP diagnostic incomplete/prohibited: ${reason}`);
  report.tcp_diagnostics=tcpNetlogDetails(log,attempts,endpoints,names);
  return report;
}
// This only observes/signals the Chrome parent. Linux Go supervision separately
// reaps/verifies the owned group and adopted descendants, even if Node is killed.
async function stopChromeParent(child, close, wait=delay) {
  const running=()=>child&&child.exitCode===null&&child.signalCode===null;
  const result= {
    parent_exit_observed:false, term_sent:false, kill_sent:false, descendants:'unknown here; authoritative owned-process result is in stability.json'
  };
  if(running()) {
    await close();
    for(let i=0; i<30&&running(); i++)await wait(100);
    if(running()) {
      result.term_sent=true;
      child.kill('SIGTERM');
    }
    for(let i=0; i<20&&running(); i++)await wait(100);
    if(running()) {
      result.kill_sent=true;
      child.kill('SIGKILL');
    }
    for(let i=0; i<20&&running(); i++)await wait(100);
  }
  result.parent_exit_observed=!!child&&!running();
  return result;
}
function chromeParentCleanupFailure(result) {
  if(!result.parent_exit_observed)return 'Chrome parent exit unknown after bounded cleanup';
  if(result.term_sent||result.kill_sent)return 'Chrome parent required signal-based cleanup';
  return null;
}
function udpDiagnosticSelfTest(baseLog,origins,endpoints) {
  for(const raw of ['https://user:secret@example.invalid/?token=secret','localhost:53','127.1:53','[fe80::1%eth0]:443','[::1]:65536','127.0.0.1','1.2.3.4:secret','127.0.0.1:443\n','[::1]:443\n'])assert.equal(literalEndpoint(raw),null);
  assert.equal(literalEndpoint('[2001:0DB8:0:0::1]:00443').endpoint,'[2001:db8::1]:443');
  assert.equal(literalEndpoint('127.0.0.1:0').scope,'loopback');
  const constants={...structuredClone(baseLog.constants),logEventTypes:{...baseLog.constants.logEventTypes,SOCKET_ALIVE:6,SOCKET_OPEN:7,SOCKET_CONNECT:8,UDP_LOCAL_ADDRESS:9,UDP_BYTES_RECEIVED:10,UDP_SEND_ERROR:11,UDP_RECEIVE_ERROR:12,HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK:13,DNS_TRANSACTION_ATTEMPT:14,UDP_PRIVATE_SECRET:15},logEventPhase:{PHASE_NONE:0,PHASE_BEGIN:1,PHASE_END:2},logSourceType:{HOST_RESOLVER_IMPL_JOB:20,UDP_CLIENT_SOCKET:21,UDP_SOCKET:22,DNS_TRANSACTION:23},netError:{'net::OK':0,ERR_ADDRESS_UNREACHABLE:-109}};
  const event=(type,phase,id,sourceType,params={})=>({type,phase,source:{id,type:sourceType},params});
  const fixture={constants,events:[
    event(13,0,100,20,{ipv6_available:false,cached:false,secret:'do-not-persist'}),
    event(6,1,101,21,{source_dependency:{id:100,type:20}}),
    event(6,1,102,22,{source_dependency:{id:101,type:21}}),
    event(7,0,101,21),
    event(4,1,102,22,{address:'[2001:db8::1]:443',bytes:'secret-payload',url:'https://user:secret@example.invalid/path?token=secret'}),
    event(4,2,102,22),
    event(8,0,101,21,{address:'[2001:db8::1]:443'}),
    event(9,0,102,22,{address:'[fe80::1234]:54321'}),
    event(6,2,102,22),event(6,2,101,21)
  ]};
  const details=udpNetlogDetails(fixture);
  assert.equal(details.details_complete,true);
  assert.deepEqual(details.failure_reasons,[]);
  assert.equal(details.sources.length,3);
  assert.equal(details.components.length,1);
  assert.equal(details.has_send_event,false);
  assert.equal(details.events.find(e=>e.event_type==='UDP_CONNECT'&&e.phase==='PHASE_END').net_error,0);
  assert(details.sources.filter(s=>UDP_TYPES.has(s.type)).every(s=>s.socket_lifetime.complete));
  assert.equal(details.events.find(e=>e.event_type==='UDP_LOCAL_ADDRESS').local_address.scope,'link_local');
  for(const text of ['secret','fe80::1234','54321'])assert(!JSON.stringify(details).includes(text));
  assert(details.probe_attribution.startsWith('unknown'));
  assert(details.limitations.some(s=>s.includes('non-capturing')));
  // Complete connect-only metadata must NOT remove the existing UDP failure.
  const combined={constants,events:[...baseLog.events,...fixture.events]};
  const guarded=netlogAudit(combined,origins,endpoints);
  assert.equal(guarded.udp_events,2);
  assert.equal(guarded.violations.filter(x=>x==='unexpected UDP_CONNECT; no UDP/DNS transport permitted').length,2);
  assert.equal(guarded.udp_diagnostics.details_complete,true);
  const failedConstants=structuredClone(constants);
  failedConstants.logSourceType.SOCKET=24;
  const failedFixture={constants:failedConstants,events:[
    ...baseLog.events.map(e=>({...e,phase:e.phase??0,source:{...e.source,type:24}})),
    event(6,1,102,22,{source_dependency:{id:101,type:21}}),
    event(6,1,101,21,{source_dependency:{id:100,type:20}}),
    event(7,0,101,21),
    event(4,1,102,22,{address:'[2001:4860:4860::8888]:443'}),
    event(4,2,102,22,{net_error:-109}),
    event(8,0,101,21,{address:'[2001:4860:4860::8888]:443',net_error:-109}),
    event(6,2,101,21),event(6,2,102,22),
    event(13,0,100,20,{ipv6_available:false,cached:false})
  ]};
  const acceptedFailure=netlogAudit(failedFixture,origins,endpoints);
  assert.equal(acceptedFailure.failed_udp_connect_operations,1);
  assert.deepEqual(acceptedFailure.violations,[]);
  const partitioned=structuredClone(failedFixture);
  for(const event of partitioned.events) {
    event.source.id=-event.source.id;
    if(event.params?.source_dependency)event.params.source_dependency.id=-event.params.source_dependency.id;
  }
  const partitionedAudit=netlogAudit(partitioned,origins,endpoints);
  assert.equal(partitionedAudit.failed_udp_connect_operations,1);
  assert.deepEqual(partitionedAudit.violations,[]);

  for(const extra of [event(5,0,102,22,{byte_count:0}),event(11,0,102,22,{net_error:-109}),event(14,0,100,20)]) {
    const rejected=netlogAudit({...failedFixture,events:[...failedFixture.events,extra]},origins,endpoints);
    assert.equal(rejected.failed_udp_connect_operations,0);
    assert(rejected.violations.length,'prohibited operation must still reject the complete audit');
  }
  const siblings=structuredClone(failedFixture);
  for(let i=200;i<400;i++)siblings.events.push(event(13,0,i,20,{source_dependency:{id:100,type:20},ipv6_available:false,cached:false}));
  const siblingAudit=netlogAudit(siblings,origins,endpoints);
  assert.equal(siblingAudit.failed_udp_connect_operations,1);
  assert.deepEqual(siblingAudit.violations,[]);
  assert(siblingAudit.udp_diagnostics.context_boundary_edges>=200);
  for(const extra of [event(13,0,401,20,{source_dependency:{id:102,type:22}}),event(11,0,402,22,{net_error:-109}),event(14,0,403,20)]) {
    const bad=netlogAudit({...siblings,events:[...siblings.events,extra]},origins,endpoints);
    assert.equal(bad.failed_udp_connect_operations,0);
    assert(bad.violations.length);
  }
  for(const mutate of [
    f=>f.events.at(-1).params.source_dependency={id:0,type:20},
    f=>f.events.at(-1).params.source_dependency={id:999999,type:20},
    f=>f.events.at(-1).params.source_dependency={id:100,type:999999},
    f=>f.events.at(-1).source.type=999999,
    f=>{f.constants.logSourceType.NEW_UNRECOGNIZED_SOURCE=999;f.events.at(-1).source.type=999;},
    f=>f.events.at(-1).type=999999,
    f=>f.events.at(-1).phase=999999,
    f=>f.events.at(-1).source={id:100,type:21}
  ]) {
    const f=structuredClone(siblings);mutate(f);
    const bad=netlogAudit(f,origins,endpoints);
    assert.equal(bad.failed_udp_connect_operations,0,'omitted context must still receive full raw validation');
    assert(bad.violations.length);
  }
  const ownedOverflow=structuredClone(failedFixture);
  for(let i=500;i<570;i++)ownedOverflow.events.push(event(4,1,i,22,{address:'[2001:4860:4860::8888]:443'}));
  const overflowAudit=netlogAudit(ownedOverflow,origins,endpoints);
  assert.equal(overflowAudit.failed_udp_connect_operations,0);
  assert(overflowAudit.udp_diagnostics.failure_reasons.some(x=>x.reason==='source_bound_exceeded'));
  const failures=input=>udpNetlogDetails(input).failure_reasons.map(r=>r.reason);
  const change=fn=>{const f=structuredClone(fixture);fn(f);return f;};
  const zero=change(f=>f.events.splice(8,0,event(5,0,102,22,{byte_count:0,bytes:'secret-zero'})));
  const z=udpNetlogDetails(zero);
  assert.equal(z.observed_send_events,1);assert(z.has_send_event&&z.has_send_attempt);
  assert(z.components[0].has_send_event);assert(z.events.some(e=>e.event_type==='UDP_BYTES_SENT'&&e.byte_count===0));
  assert(failures(zero).includes('udp_send_event_including_zero_bytes'));
  assert(netlogAudit({constants,events:[...baseLog.events,...zero.events]},origins,endpoints).violations.some(x=>x==='unexpected UDP_BYTES_SENT; no UDP/DNS transport permitted'));
  const failedReconnect=change(f=>f.events.splice(8,0,event(4,1,102,22,{address:'[2001:db8::2]:443'}),event(4,2,102,22,{net_error:-109}),event(5,0,102,22,{byte_count:0})));
  assert(failures(failedReconnect).includes('datagram_destination_unknown'));
  const sendError=change(f=>f.events.splice(8,0,event(11,0,102,22,{net_error:-109})));
  const failedSend=udpNetlogDetails(sendError);
  assert.equal(failedSend.observed_send_errors,1);assert(failedSend.has_send_attempt&&!failedSend.has_send_event);
  assert(failures(sendError).includes('udp_send_attempt_error'));
  for(const [edit,reason]of [
    [f=>f.events[4].params.address='http://user:secret@bad/?token=secret','endpoint_not_literal_ip_port'],
    [f=>f.events.splice(5,1),'connect_end_missing'],
    [f=>f.events[5].params.net_error='secret','net_error_unknown'],
    [f=>delete f.events[2].params.source_dependency,'socket_dependency_missing'],
    [f=>f.events[2].params.source_dependency=null,'dependency_identity_missing'],
    [f=>f.events.pop(),'socket_lifetime_incomplete'],
    [f=>f.events[5].phase=99,'event_phase_unknown'],
    [f=>delete f.constants.logSourceType,'source_type_unknown'],
    [f=>delete f.constants.netError,'diagnostic_constants_missing'],
    [f=>f.events[5].source.type=21,'source_type_conflict'],
    [f=>f.events[5].source.id=0,'udp_source_identity_missing'],
    [f=>f.events.splice(8,0,event(15,0,102,22,{secret:'private'})),'udp_event_unknown'],
    [f=>f.events.splice(8,0,event(14,0,100,20,{source_dependency:{id:102,type:22},qname:'secret.invalid'})),'dns_or_mdns_event'],
    [f=>f.events.splice(8,0,event(5,0,102,22,{byte_count:-1})),'datagram_byte_count_unknown']
  ]) {
    const f=change(edit),r=udpNetlogDetails(f);
    assert(r.failure_reasons.some(x=>x.reason===reason),`missing negative ${reason}`);
    assert.equal(r.details_complete,false);
    assert(!JSON.stringify(r).includes('secret'));
    assert(Buffer.byteLength(JSON.stringify(r))<=UDP_DETAIL_LIMITS.bytes);
  }
  const eventOverflow=change(f=>{for(let i=0;i<300;i++)f.events.push(event(13,0,100,20,{ipv6_available:false,cached:true}));});
  const bounded=udpNetlogDetails(eventOverflow);
  assert(bounded.overflow&&!bounded.details_complete);
  assert(bounded.events.length<=UDP_DETAIL_LIMITS.events);
  assert(failures(eventOverflow).includes('event_detail_bound_exceeded'));
  const sourceOverflow=change(f=>{for(let i=200;i<270;i++)f.events.push(event(4,1,i,22,{address:'127.0.0.1:443'}));});
  const sourceBounded=udpNetlogDetails(sourceOverflow);
  assert(sourceBounded.overflow&&sourceBounded.sources.length<=UDP_DETAIL_LIMITS.sources);
  assert(failures(sourceOverflow).includes('source_bound_exceeded'));
  const depthOverflow=change(f=>{for(let i=0;i<12;i++)f.events.push(event(13,0,100+i*100,20,{source_dependency:{id:200+i*100,type:20},ipv6_available:false,cached:false}));});
  assert(!failures(depthOverflow).includes('dependency_depth_exceeded'),'unrelated parent ancestry is outside the ownership projection');
  const edgeOverflow=change(f=>{for(let a=100;a<114;a++)for(let b=100;b<114;b++)if(a!==b)f.events.push(event(13,0,a,22,{source_dependency:{id:b,type:22},ipv6_available:false,cached:false}));});
  assert(failures(edgeOverflow).includes('dependency_edge_bound_exceeded'));
  assert(Buffer.byteLength(JSON.stringify(udpNetlogDetails(edgeOverflow)))<=UDP_DETAIL_LIMITS.bytes);
  const byteOverflow={constants,events:[event(13,0,100,20,{ipv6_available:false,cached:false})]};
  for(let i=0;i<63;i++) {
    const id=-2147483648+i;
    byteOverflow.events.push(event(6,1,id,22,{source_dependency:{id:100,type:20}}),event(4,1,id,22,{address:'[2001:db8:1234:5678:9abc:def0:1111:2222]:65535'}),event(4,2,id,22),event(6,2,id,22));
  }
  const byteBounded=udpNetlogDetails(byteOverflow);
  assert(byteBounded.overflow&&!byteBounded.details_complete);
  assert(byteBounded.failure_reasons.some(x=>x.reason==='diagnostic_byte_bound_exceeded'));
  assert(Buffer.byteLength(JSON.stringify(byteBounded))<=UDP_DETAIL_LIMITS.bytes);
}
// Runs in the real page; also tested with a minimal DOM fixture below.
function focusLegacyDangerDisclosure(doc=document) {
  const button=doc.querySelector('.btn-reject');
  if(!button)throw new Error('legacy danger button missing');
  const group=button.closest('details');
  if(!group)throw new Error('legacy danger disclosure missing');
  if(group.open)return false;
  const summary=group.querySelector('summary');
  if(!summary)throw new Error('legacy danger summary missing');
  summary.focus();
  return true;
}
function skipFocusState(doc=document,win=window) {
  const el=doc.activeElement,s=win.getComputedStyle(el),r=el.getBoundingClientRect(),v=win.visualViewport;
  return {style:s.outlineStyle,width:parseFloat(s.outlineWidth),visible:r.top>=0&&r.bottom<=win.innerHeight,
    focus:el.matches(':focus'),focus_visible:el.matches(':focus-visible'),top:r.top,bottom:r.bottom,
    computed_top:s.top,position:s.position,transform:s.transform,viewport_height:win.innerHeight,
    scroll_x:win.scrollX,scroll_y:win.scrollY,client_height:doc.documentElement.clientHeight,
    visual_viewport:v?{offset_top:v.offsetTop,page_top:v.pageTop,height:v.height,scale:v.scale}:null};
}
// Real-page checks for sibling content that may overlap without main overflow.
function responsiveLayoutIssues(doc=document) {
  const issues=[];
  const pairs=[['.finding-source-mix li','span','meter','source-label-meter'],['.cve-summary','.cve-summary-main','.cve-summary-meta','cve-summary-controls']];
  for(const [root,left,right,label]of pairs)for(const el of [...doc.querySelectorAll(root)].slice(0,32)) {
    const a=el.querySelector(left)?.getBoundingClientRect(),b=el.querySelector(right)?.getBoundingClientRect();
    if(!a||!b){issues.push(label+'-missing');continue;}
    if(Math.min(a.right,b.right)-Math.max(a.left,b.left)>1&&Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top)>1)issues.push(label+'-overlap');
  }
  return issues;
}
function shouldCapture(info,viewport) {
  return info.screenshot||(info.name==='legacy-reports'&&viewport.name==='mobile');
}
function checkCaptureBudget(cases) {
  const count=['desktop','mobile'].reduce((n,name)=>n+cases.filter(info=>shouldCapture(info,{name})).length,0);
  assert.equal(count,29,'required screenshot matrix changed');
  assert(count+2<=31,'planned Node artifacts exceed file budget');
  assert(count+3<=32,'planned artifacts including stability exceed Go file budget');
  return count;
}
function tcpDiagnosticSelfTest(baseLog,origins,endpoints) {
  const groups=[],group=(name,test)=>{test();groups.push(name);};
  const anchor=9223372036854000000n;
  const fixture=()=>{
    const f=structuredClone(baseLog);
    for(let i=0;i<f.events.length;i++)f.events[i].time=String(anchor+BigInt(i));
    return f;
  };
  const pending=()=>{const f=fixture();f.events.splice(3,1);return f;};
  const audit=f=>netlogAudit(f,origins,endpoints);
  const project=f=>audit(f).tcp_diagnostics;
  const jsonBytes=value=>Buffer.byteLength(JSON.stringify(value,null,2)+'\n');
  const strip=value=>{const copy=structuredClone(value);delete copy.network_audit.tcp_diagnostics;return copy;};
  group('normal',()=>{
    const d=project(fixture());
    assert.equal(d.unfinished_key_count,0);assert.deepEqual(d.records,[]);assert.equal(d.projection_status,'complete');
    assert.deepEqual(audit(fixture()).violations,[]);
  });
  group('missing-END-and-index-zero',()=>{
    for(const [removed,indexes]of [[[3],[0]],[[2],[1]],[[3,2],[0,1]]]) {
      const f=fixture();for(const i of removed)f.events.splice(i,1);
      const a=audit(f),d=a.tcp_diagnostics;
      assert.equal(d.unfinished_key_count,indexes.length);assert.deepEqual(d.records.map(row=>row.begin_index),indexes);
      assert(a.violations.includes('unfinished TCP attempt; transport outcome unknown'));
    }
  });
  group('mismatched-and-reordered-END',()=>{
    for(const change of [f=>f.events[2].type=1,f=>f.events[2].source.id=2,f=>{[f.events[0],f.events[3]]=[f.events[3],f.events[0]];},f=>f.events.push(structuredClone(f.events[2])),f=>f.events[4].source.id=2]) {
      const f=fixture();change(f);assert(audit(f).violations.length);
    }
  });
  group('duplicate-BEGIN-keeps-old-key-semantics',()=>{
    const f=pending();f.events.splice(1,0,structuredClone(f.events[0]));
    const d=project(f);assert.equal(d.unfinished_key_count,1);assert.equal(d.records[0].begin_index,1);
    f.events.push({type:1,phase:2,source:{id:1},time:String(anchor+9n)});
    assert.equal(project(f).unfinished_key_count,0);assert.deepEqual(audit(f).violations,[]);
  });
  group('exact-endpoint-verdict-counts',()=>{
    const f=pending();f.events[0].params={address_list:['127.0.0.1:123','127.0.0.1:0123',null,'synthetic-private-endpoint'],address:'127.0.0.1:123',remote_address:'203.0.113.88:443',peer_address:{private:'synthetic-private-endpoint'}};
    const d=project(f);assert.deepEqual(d.records[0].begin_endpoint_counts,{total:7,allowlisted:2,non_allowlisted:3,non_string:2});
    const missing=pending();missing.events[0].params={};
    assert.equal(project(missing).records[0].begin_endpoint_counts.total,0);assert(audit(missing).violations.some(s=>s.startsWith('missing TCP_CONNECT endpoint')));
    for(const text of ['synthetic-private-endpoint','203.0.113.88','127.0.0.1'])assert(!JSON.stringify(d).includes(text));
  });
  group('signed-source-ID-and-no-coercion',()=>{
    for(const id of [-2147483648,-1,1,2147483647,0,-0,-2147483649,2147483648,4294967295,1.5,'synthetic-private-ID',null,undefined,NaN,Infinity]) {
      const f=pending();for(const e of f.events)e.source.id=id;
      const row=project(f).records[0],valid=validNetLogSourceID(id);
      assert.equal(row.source_id,valid?id:null);assert.equal(row.identity_status,valid?'valid':'invalid');
      if(!valid){assert.equal(row.same_id_event_count,null);assert.deepEqual(row.recent_same_id_events,[]);}
    }
  });
  group('fixed-recursive-schema-and-private-markers',()=>{
    const f=pending(),marker='synthetic-private-marker';
    f.constants.logEventTypes[marker]=99;f.constants.logSourceType={[marker]:7};
    f.events[0].params={address_list:[marker],url:`https://user:${marker}@host.invalid/${marker}?token=${marker}#${marker}`,headers:{authorization:marker},profile:marker,body:{nested:marker}};
    f.events[0].source.type=marker;
    f.events.push({type:99,phase:99,source:{id:1,type:marker},time:marker,params:{secret:marker}});
    const d=project(f);
    const keys=(value,expected)=>assert.deepEqual(Object.keys(value).sort(),expected.split(' ').sort());
    keys(d,'schema_version scope matching_basis limits unfinished_key_count recorded_key_count omitted_key_count projection_status reason_counts records');
    keys(d.limits,'pending_records same_id_events_per_record bytes relative_time_ms');
    for(const row of d.reason_counts)keys(row,'reason count');
    for(const row of d.records) {
      keys(row,'source_id identity_status event_type begin_index relative_time_ms begin_endpoint_counts same_id_event_count omitted_same_id_event_count recent_same_id_events');
      keys(row.begin_endpoint_counts,'total allowlisted non_allowlisted non_string');
      for(const e of row.recent_same_id_events)keys(e,'event_index event_type phase relative_time_ms');
    }
    const strings=new Set([TCP_DETAIL_SCOPE,'source_id_event_name_latest_begin','complete','partial','summary_only','unavailable','valid','invalid','TCP_CONNECT','TCP_CONNECT_ATTEMPT','SOCKET_BYTES_SENT','SOCKET_ALIVE','OTHER','PHASE_BEGIN','PHASE_END','PHASE_NONE','UNKNOWN',...TCP_DETAIL_REASONS]);
    const leaf=value=>{if(value===null)return;if(Array.isArray(value)){value.forEach(leaf);return;}if(typeof value==='object'){Object.values(value).forEach(leaf);return;}if(typeof value==='string')assert(strings.has(value));else assert(Number.isSafeInteger(value));};
    leaf(d);
    for(const text of [marker,'host.invalid','https://','authorization','profile','headers','token='])assert(!JSON.stringify(d).includes(text));
    assert(d.records[0].recent_same_id_events.some(e=>e.event_type==='OTHER'&&e.phase==='UNKNOWN'));
  });
  group('unknown-and-ambiguous-metadata',()=>{
    const f=pending();f.events.push({type:999,phase:999,source:{id:1},time:String(anchor+8n)});
    let last=project(f).records[0].recent_same_id_events.at(-1);assert.equal(last.event_type,'OTHER');assert.equal(last.phase,'UNKNOWN');
    f.constants.logEventPhase.PHASE_NONE=1;f.events.at(-1).phase=1;
    last=project(f).records[0].recent_same_id_events.at(-1);assert.equal(last.phase,'UNKNOWN');
    f.constants.logEventTypes['synthetic-private-alias']=1;
    assert(!JSON.stringify(project(f)).includes('synthetic-private-alias'));
  });
  group('relative-timestamp-boundaries',()=>{
    for(const delta of [0n,1n,300000n]) {
      const f=fixture();f.events.splice(2,1);f.events[1].time=String(anchor+delta);
      assert.equal(project(f).records[0].relative_time_ms,Number(delta));
    }
    for(const value of [undefined,null,1,1.5,'',' 1','1 ','01','-0','1.0','1e3','synthetic-private-time','9223372036854775808','-9223372036854775809','12345678901234567890',String(anchor-1n),String(anchor+300001n)]) {
      const f=fixture();f.events.splice(2,1);f.events[1].time=value;
      assert.equal(project(f).records[0].relative_time_ms,null);
    }
    const f=pending();f.events[0].time='synthetic-private-anchor';
    assert.equal(project(f).records[0].relative_time_ms,null);assert(!JSON.stringify(project(f)).includes(String(anchor)));
  });
  group('record-context-byte-and-event-bounds',()=>{
    // Replacing the first inserted key moves its latest BEGIN to the end of
    // index order without moving that key's Map insertion position.
    for(const size of [16,17]) {
      const f=fixture();
      for(let id=2;id<size+2;id++)f.events.push({type:1,phase:1,source:{id},params:{address:'127.0.0.1:123'},time:String(anchor+BigInt(id))});
      f.events.push({type:1,phase:1,source:{id:2},params:{address:'127.0.0.1:123'},time:String(anchor+99n)});
      const d=project(f),expected=[6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21];
      assert.equal(d.unfinished_key_count,size);assert.equal(d.recorded_key_count,16);assert.equal(d.omitted_key_count,size-16);
      assert.deepEqual(d.records.map(row=>row.begin_index),expected);
      assert.deepEqual(d.records.map(row=>row.source_id),size===16?[3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,2]:[3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18]);
      for(const row of d.records)assert.deepEqual(row.recent_same_id_events.map(e=>e.event_index),row.source_id===2?[5,21]:[row.source_id+3]);
      assert(!d.reason_counts.some(row=>row.reason==='diagnostic_byte_bound'),'key-cap fixture must not trim by bytes');
      assert.equal(d.reason_counts.find(row=>row.reason==='pending_record_limit')?.count??0,size-16);
    }
    const context=pending();
    let d=project(context);assert.deepEqual(d.records[0].recent_same_id_events.map(e=>e.event_index),[0,1,2,3]);
    assert.equal(d.records[0].same_id_event_count,4);assert.equal(d.records[0].omitted_same_id_event_count,0);
    context.events.push({type:999,phase:999,source:{id:1},time:String(anchor+9n)});
    d=project(context);assert.deepEqual(d.records[0].recent_same_id_events.map(e=>e.event_index),[1,2,3,4]);
    assert.equal(d.records[0].same_id_event_count,5);assert.equal(d.records[0].omitted_same_id_event_count,1);
    const many=fixture();
    for(let id=2;id<18;id++) {
      many.events.push({type:1,phase:1,source:{id},params:{address:'127.0.0.1:123'},time:String(anchor+BigInt(id))});
      for(let i=0;i<5;i++)many.events.push({type:999,phase:999,source:{id},time:String(anchor+BigInt(id+i))});
    }
    d=project(many);assert(tcpDiagnosticBytes(d)<=16384);assert.equal(d.projection_status,'partial');
    assert.equal(d.recorded_key_count,13);assert.equal(d.omitted_key_count,3);
    assert.deepEqual(d.records.map(row=>row.begin_index),[5,11,17,23,29,35,41,47,53,59,65,71,77]);
    for(const row of d.records) {
      assert.deepEqual(row.recent_same_id_events.map(e=>e.event_index),[row.begin_index+2,row.begin_index+3,row.begin_index+4,row.begin_index+5]);
      assert.equal(row.same_id_event_count,6);assert.equal(row.omitted_same_id_event_count,2);
    }
    assert.equal(d.reason_counts.find(row=>row.reason==='diagnostic_byte_bound').count,3);
    assert(!d.reason_counts.some(row=>row.reason==='pending_record_limit'),'byte-cap fixture has only 16 pending keys');
    const oneMore=structuredClone(d);
    oneMore.records.push({source_id:15,identity_status:'valid',event_type:'TCP_CONNECT',begin_index:83,relative_time_ms:15,
      begin_endpoint_counts:{total:1,allowlisted:1,non_allowlisted:0,non_string:0},same_id_event_count:6,omitted_same_id_event_count:2,
      recent_same_id_events:[85,86,87,88].map((event_index,i)=>({event_index,event_type:'OTHER',phase:'UNKNOWN',relative_time_ms:16+i}))});
    oneMore.recorded_key_count=14;oneMore.omitted_key_count=2;oneMore.reason_counts.find(row=>row.reason==='diagnostic_byte_bound').count=2;
    assert(tcpDiagnosticBytes(oneMore)>16384,'the next exact prefix must exceed the persisted-byte cap');
    const large=pending();while(large.events.length<100000)large.events.push({type:999,phase:0,source:{id:2},time:String(anchor)});
    assert.equal(project(large).unfinished_key_count,1);large.events.push(large.events.at(-1));
    assert.throws(()=>audit(large),/invalid\/bounded NetLog events/);
  });
  group('deterministic-nonmutating-projection',()=>{
    const f=pending(),before=structuredClone(f),keys=new Map([['private-key',0]]),beforeKeys=[...keys],beforeEndpoints=[...endpoints];
    const names=new Map(Object.entries(f.constants.logEventTypes).map(([name,value])=>[value,name]));
    for(let i=0;i<5000;i++)names.set(1000+i,'synthetic-unused-event-'+i);
    const beforeNames=[...names];
    for(const method of ['set','delete','clear','entries','values',Symbol.iterator])Object.defineProperty(names,method,{value(){throw new Error('shared event Map must be read-only and never enumerated');}});
    // The projection must reuse the passed Map, never enumerate raw constants.
    const a=tcpNetlogDetails(f,keys,endpoints,names),b=tcpNetlogDetails(f,keys,endpoints,names);
    assert.notEqual(a.projection_status,'unavailable');assert.deepEqual(a,b);assert.deepEqual(f,before);
    const probe=structuredClone(f);
    Object.defineProperty(probe.constants,'logEventTypes',{get(){throw new Error('raw event constants must not be reread');}});
    assert.deepEqual(tcpNetlogDetails(probe,keys,endpoints,names),a);
    assert.deepEqual([...Map.prototype.entries.call(names)],beforeNames);assert.deepEqual([...keys],beforeKeys);assert.deepEqual([...endpoints],beforeEndpoints);
    assert.deepEqual(a.records.map(row=>row.begin_index),[...a.records.map(row=>row.begin_index)].sort((a,b)=>a-b));
    for(const row of a.records)assert.deepEqual(row.recent_same_id_events.map(e=>e.event_index),[...row.recent_same_id_events.map(e=>e.event_index)].sort((a,b)=>a-b));
  });
  group('existing-JSON-budget-preserves-original-evidence',()=>{
    const d=project(pending()),limit=256*1024;
    const make=bytes=>{
      const baseline={padding:'',network_audit:{violations:['unfinished TCP attempt; transport outcome unknown'],existing_field:'kept'}};
      baseline.padding='x'.repeat(bytes-jsonBytes(baseline));
      const checks=structuredClone(baseline);checks.network_audit.tcp_diagnostics=structuredClone(d);
      return {baseline,checks};
    };
    const sample=make(1000),overhead=jsonBytes(sample.checks)-jsonBytes(sample.baseline);
    for(const [bytes,status]of [[limit-overhead,'full'],[limit-overhead+1,'summary_only'],[limit,'omitted'],[limit+1,'omitted']]) {
      const {baseline,checks}=make(bytes);fitTCPDiagnosticBudget(checks);
      assert.deepEqual(strip(checks),baseline);
      if(status==='full')assert.deepEqual(checks.network_audit.tcp_diagnostics,d);
      else if(status==='summary_only')assert.equal(checks.network_audit.tcp_diagnostics.projection_status,status);
      else assert(!Object.hasOwn(checks.network_audit,'tcp_diagnostics'));
      assert.equal(jsonBytes(checks)<=limit,bytes<=limit);
    }
    const summarySample=make(limit-overhead+1);fitTCPDiagnosticBudget(summarySample.checks);
    const summaryOverhead=jsonBytes(summarySample.checks)-jsonBytes(summarySample.baseline);
    for(const [bytes,status]of [[limit-summaryOverhead,'summary_only'],[limit-summaryOverhead+1,'omitted']]) {
      const {baseline,checks}=make(bytes);fitTCPDiagnosticBudget(checks);assert.deepEqual(strip(checks),baseline);
      if(status==='summary_only'){assert.equal(checks.network_audit.tcp_diagnostics.projection_status,status);assert.equal(jsonBytes(checks),limit);}
      else {assert(!Object.hasOwn(checks.network_audit,'tcp_diagnostics'));assert.equal(bytes+summaryOverhead,limit+1);}
    }
  });
  group('unavailable-is-not-a-transport-verdict',()=>{
    const d=tcpNetlogDetails(fixture(),{size:1,values(){throw new Error('synthetic-private-exception');}},endpoints,new Map());
    assert.equal(d.unfinished_key_count,1);assert.equal(d.projection_status,'unavailable');assert.deepEqual(d.reason_counts,[{reason:'projection_unavailable',count:1}]);
    assert(!JSON.stringify(d).includes('synthetic-private-exception'));
    assert(audit(pending()).violations.includes('unfinished TCP attempt; transport outcome unknown'));
    assert.throws(()=>audit({events:[]}),/missing NetLog constant/);
  });
  group('UDP-and-DNS-rejections-remain',()=>{
    for(const [type,name]of [[5,'UDP_BYTES_SENT'],[99,'DNS_TRANSACTION_ATTEMPT']]) {
      const f=fixture();f.constants.logEventTypes[name]=type;f.events.push({type,source:{id:2},params:{byte_count:0},time:String(anchor+9n)});
      assert(audit(f).violations.some(text=>text===`unexpected ${name}; no UDP/DNS transport permitted`));
    }
  });
  assert.equal(groups.length,14);
  console.log('PASS TCP diagnostic 14 groups: '+groups.join(', ')+'; synthetic only');
}
async function selfTest() {
  const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return{promise,resolve,reject};};
  const failures=[],cancellations=[],decisions=new FetchDecisions((error,metadata)=>failures.push({error:error.message,...metadata}),metadata=>cancellations.push(metadata));
  const first=deferred(),second=deferred();
  decisions.track(()=>first.promise,{safe:true});
  let closed=false;
  const teardown=decisions.drain().then(()=>{closed=true;});
  await delay(0);
  assert.equal(closed,false,'teardown raced an outstanding continuation');
  decisions.track(()=>second.promise,{safe:false});
  first.resolve();
  await delay(0);
  assert.equal(closed,false,'drain missed a decision arriving during settlement');
  second.reject(new Error('unsafe request blocking failed'));
  await teardown;
  assert.deepEqual(failures,[{error:'unsafe request blocking failed',safe:false}]);
  const staleSafeError=new Error('CDP Fetch.continueRequest: {"code":-32602,"message":"Invalid InterceptionId."}');
  assert.equal(isBenignSafeFetchCancellation(staleSafeError,{safe:true,fixture_origin:true,method:'GET',response_stage:false}),true);
  assert.equal(isBenignSafeFetchCancellation(staleSafeError,{safe:true,fixture_origin:false,method:'GET',response_stage:false}),false,'about:blank must not qualify as an allowlisted fixture origin');
  assert.equal(isFetchResponseStage({}),false);
  assert.equal(isFetchResponseStage({responseStatusCode:200}),true);
  assert.equal(isFetchResponseStage({responseErrorReason:'Aborted'}),true,'responseErrorReason alone identifies response stage');
  decisions.track(()=>Promise.reject(staleSafeError),{safe:true,fixture_origin:true,method:'GET',response_stage:false});
  await decisions.drain();
  assert.equal(cancellations.length,1,'stale safe requests should be recorded as benign cancellations');
  assert.equal(failures.length,1,'benign safe cancellation should not be a violation');
  decisions.track(()=>Promise.reject(new Error('CDP Fetch.continueRequest: {"code":-32602,"message":"Invalid InterceptionId."}')),{safe:false,fixture_origin:false,method:'POST',response_stage:false});
  await decisions.drain();
  assert.equal(failures.length,2,'unsafe request cancellation must remain fatal');
  decisions.track(()=>Promise.reject(new Error('CDP Fetch.continueRequest: {"code":-32602,"message":"Invalid InterceptionId."}')),{safe:true,fixture_origin:true,method:'GET',response_stage:true});
  await decisions.drain();
  assert.equal(failures.length,3,'response-stage cancellation must remain fatal');
  decisions.track(()=>Promise.reject(new Error('connection reset')),{safe:true,fixture_origin:true,method:'GET',response_stage:false});
  await decisions.drain();
  assert.equal(failures.length,4,'other safe request errors must remain fatal');
  decisions.track(()=>Promise.reject(new Error('CDP Fetch.continueRequest: {"code":-32602,"message":"Invalid InterceptionId. unrelated detail"}')),{safe:true,fixture_origin:true,method:'GET',response_stage:false});
  await decisions.drain();
  assert.equal(failures.length,5,'a non-exact CDP error must remain fatal');
  assert.equal(cancellations.length,1,'only exact stale-interception errors may be recorded as benign');
  const hung=deferred();
  decisions.track(()=>hung.promise,{safe:true});
  await assert.rejects(decisions.drain(5),/deadline/);
  assert.equal(decisions.pending.size,1,'deadline must not discard pending decisions');
  hung.resolve();
  await decisions.drain();

  const focusDoc={activeElement:{matches:()=>true,getBoundingClientRect:()=>({top:-100,bottom:-53})},documentElement:{clientHeight:844}};
  const focusWindow={getComputedStyle:()=>({outlineStyle:'solid',outlineWidth:'3px',top:'12px',position:'fixed',transform:'none'}),innerHeight:844,scrollX:0,scrollY:0,visualViewport:{offsetTop:0,pageTop:0,height:844,scale:1}};
  assert.equal(skipFocusState(focusDoc,focusWindow).visible,false);
  focusDoc.activeElement.getBoundingClientRect=()=>({top:12,bottom:59});
  assert.equal(skipFocusState(focusDoc,focusWindow).visible,true);

  const rect=(left,top,right,bottom)=>({getBoundingClientRect:()=>({left,top,right,bottom})});
  const layoutDoc=(a,b)=>({querySelectorAll:selector=>selector==='.finding-source-mix li'?[{querySelector:s=>s==='span'?a:b}]:[]});
  assert.deepEqual(responsiveLayoutIssues(layoutDoc(rect(0,0,100,20),rect(50,0,150,20))),['source-label-meter-overlap']);
  assert.deepEqual(responsiveLayoutIssues(layoutDoc(rect(0,0,100,20),rect(0,30,100,40))),[]);

  const captureCases=Array.from({length:14},(_,i)=>({name:`original-${i}`,screenshot:true}));
  captureCases.push({name:'legacy-reports',screenshot:false},{name:'empty-findings',screenshot:false});
  assert.equal(checkCaptureBudget(captureCases),29);
  for(const info of captureCases.slice(0,14))for(const name of ['desktop','mobile'])assert(shouldCapture(info,{name}));
  assert.equal(shouldCapture(captureCases[14],{name:'desktop'}),false);
  assert.equal(shouldCapture(captureCases[14],{name:'mobile'}),true);
  assert.throws(()=>checkCaptureBudget(captureCases.map(info=>({...info,screenshot:true}))));
  assert.throws(()=>checkCaptureBudget(captureCases.slice(1)));

  let summaryFocuses=0;
  const group={open:false,querySelector:()=>({focus:()=>summaryFocuses++})};
  const dangerDocument={querySelector:()=>({closest:()=>group})};
  assert.equal(focusLegacyDangerDisclosure(dangerDocument),true);
  assert.equal(summaryFocuses,1);
  group.open=true;
  assert.equal(focusLegacyDangerDisclosure(dangerDocument),false);
  assert.equal(summaryFocuses,1,'restored open details must not be toggled closed');
  assert.throws(()=>focusLegacyDangerDisclosure({querySelector:()=>null}));
  const input=new PassThrough(), output=new PassThrough(), client=new CDP(input, output);
  let sent='';
  input.on('data', b=>sent+=b.toString());
  const pending=client.call('Browser.getVersion');
  assert(sent.endsWith('\0'));
  output.write('{"id":1,"res');
  output.write('ult":{"product":"synthetic protocol framing only"}}\0');
  assert.equal((await pending).product, 'synthetic protocol framing only');
  assert(client.receivedBytes>0);
  assert.equal(client.receivedMessages,1);
  assert.equal(client.buffer.length,0);
  client.close(new Error('self-test done'));
  assert(allowedOrigin('http://127.0.0.1:123/assets', new Set(['http://127.0.0.1:123'])));
  for(const u of ['https://example.invalid', 'http://localhost:123', 'http://127.0.0.1:124', 'file:///tmp/x', 'data:text/html,x', 'http://user:secret@127.0.0.1:123'])assert(!allowedOrigin(u, new Set(['http://127.0.0.1:123'])));
  assert(contrast('rgb(6, 43, 36)', 'rgb(120, 221, 194)')>=4.5);
  const origins=new Set(['http://127.0.0.1:123', 'http://127.0.0.1:124', 'http://127.0.0.1:125']), policy=networkPolicy(origins, 'http://127.0.0.1:126');
  assert.equal(policy.resolver, 'MAP * ^NOTFOUND, EXCLUDE 127.0.0.1');
  assert.equal(policy.bypass, '<-loopback>;http://127.0.0.1:123;http://127.0.0.1:124;http://127.0.0.1:125');
  assert(!policy.endpoints.has('127.0.0.1:127'));
  assert.equal(networkLabel('https://user:secret@example.invalid/path?token=secret#fragment'), 'https://example.invalid/path');
  assert.equal(networkLabel('invalid target?secret'), '[unparseable network target]');
  const navigationEvents=[];
  for(let i=0;i<70;i++)navigationDiagnostic(navigationEvents,'document-response',{
    url:'http://127.0.0.1:123/assets/not-an-id?token=secret#fragment',status:404,
    error:'failed http://127.0.0.1:123/path?token=secret',headers:{authorization:'secret'}
  });
  assert.equal(navigationEvents.length,64);
  assert.equal(navigationEvents.at(-1).status,404);
  assert.equal(navigationEvents.at(-1).url,'http://127.0.0.1:123/assets/not-an-id');
  assert(!JSON.stringify(navigationEvents).includes('secret'));
  assert(!JSON.stringify(navigationEvents).includes('headers'));
  assert(Buffer.byteLength(JSON.stringify(navigationEvents))<64*1024);
  assert(internalTarget( {
    type:'browser_ui', url:'chrome://test'
  }));
  assert(!internalTarget( {
    type:'service_worker', url:'https://example.invalid/'
  }));
  assert(!internalTarget( {
    type:'page', url:'chrome://test'
  }));
  const constants= {
    logEventTypes: {
      TCP_CONNECT:1, TCP_CONNECT_ATTEMPT:2, SOCKET_BYTES_SENT:3, UDP_CONNECT:4, UDP_BYTES_SENT:5
    }, logEventPhase: {
      PHASE_BEGIN:1, PHASE_END:2
    }
  };
  const log= {
    constants, events:[ {
      type:1, phase:1, source: {
        id:1
      }, params: {
        address_list:['127.0.0.1:123'], url:'https://example.invalid/path?secret=bad'
      }
    }, {
      type:2, phase:1, source: {
        id:1
      }, params: {
        address:'127.0.0.1:123'
      }
    }, {
      type:2, phase:2, source: {
        id:1
      }
    }, {
      type:1, phase:2, source: {
        id:1
      }
    }, {
      type:3, source: {
        id:1
      }
    }]
  };
  udpDiagnosticSelfTest(log,origins,policy.endpoints);
  tcpDiagnosticSelfTest(log,origins,policy.endpoints);
  const audit=netlogAudit(log, origins, policy.endpoints);
  assert.deepEqual(audit.violations, []);
  assert.deepEqual(audit.non_fixture_url_attempts, ['https://example.invalid/path']);
  assert(!JSON.stringify(audit).includes('secret'));
  assert(!scrubNetworkText('failed https://example.invalid/path?key=secret#fragment').includes('secret'));
  const escaped=structuredClone(log);
  escaped.events[1].params.address='203.0.113.1:443';
  assert(netlogAudit(escaped, origins, policy.endpoints).violations.length);
  const unknown=structuredClone(log);
  unknown.events[0].params.address_list=[];
  unknown.events[1].params= {};
  assert(netlogAudit(unknown, origins, policy.endpoints).violations.length);
  assert.throws(()=>netlogAudit( {
    events:[]
  }, origins, policy.endpoints));
  const udp=structuredClone(log);
  udp.events.push( {
    type:5
  });
  assert(netlogAudit(udp, origins, policy.endpoints).violations.length);
  const missingIdentity=structuredClone(log);
  missingIdentity.events[0].source= {};
  assert(netlogAudit(missingIdentity, origins, policy.endpoints).violations.length);
  const unpaired=structuredClone(log);
  unpaired.events.pop();
  unpaired.events.pop();
  assert(netlogAudit(unpaired, origins, policy.endpoints).violations.length);
  const statusEval=node=>new Function('document', `return ${CODEX_READY}`)( {
    querySelector:()=>node
  });
  assert.equal(statusEval(null), false);
  assert.equal(statusEval( {
    textContent:'確認中'
  }), false);
  assert.equal(statusEval( {
    textContent:'unrelated completion'
  }), false);
  assert.equal(statusEval( {
    textContent:'Synthetic offline browser QA; no CLI invoked'
  }), true);
  const ended= {
    exitCode:0, signalCode:null
  };
  const clean=await stopChromeParent(ended, async()=> {});
  assert(clean.parent_exit_observed);
  assert.equal(chromeParentCleanupFailure(clean), null);
  const termZero={exitCode:null,signalCode:null,signals:[],kill(s){this.signals.push(s);this.exitCode=0;}};
  const termRecovered=await stopChromeParent(termZero, async()=> {}, async()=> {});
  assert(termRecovered.parent_exit_observed&&termRecovered.term_sent&&!termRecovered.kill_sent);
  assert.equal(termZero.exitCode,0);
  assert.deepEqual(termZero.signals,['SIGTERM']);
  assert.equal(chromeParentCleanupFailure(termRecovered),'Chrome parent required signal-based cleanup');
  const stubborn= {
    exitCode:null, signalCode:null, signals:[], kill(s) {
      this.signals.push(s);
      if(s==='SIGKILL')this.signalCode=s;
    }
  };
  const stopped=await stopChromeParent(stubborn, async()=> {}, async()=> {});
  assert(stopped.parent_exit_observed&&stopped.kill_sent);
  assert(chromeParentCleanupFailure(stopped));
  assert.deepEqual(stubborn.signals, ['SIGTERM', 'SIGKILL']);
  const unknownExit= {
    exitCode:null, signalCode:null, kill() {}
  };
  const unknownCleanup=await stopChromeParent(unknownExit, async()=> {}, async()=> {});
  assert.equal(unknownCleanup.parent_exit_observed, false);
  assert(chromeParentCleanupFailure(unknownCleanup));
  assert.throws(()=>argumentsMap(['--out', 'a', '--out', 'b']));
  const errorIn=new PassThrough(), errorOut=new PassThrough(), errorClient=new CDP(errorIn, errorOut);
  const rejected=errorClient.call('Runtime.evaluate');
  errorOut.write('{"id":1,"error":{"message":"synthetic protocol error"}}\0');
  await assert.rejects(rejected, /synthetic protocol error/);
  errorClient.close(new Error('done'));
  const header=Buffer.alloc(24);
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(header);
  header.write('IHDR', 12);
  header.writeUInt32BE(1440, 16);
  header.writeUInt32BE(1000, 20);
  assert.deepEqual(pngSize(header), {
    width:1440, height:1000
  });
  assert.throws(()=>pngSize(Buffer.alloc(24)));
  await (await import('./test_browser_startup_diagnostics.mjs')).testStartupDiagnostics({CDP, fitTCPDiagnosticBudget});
  console.log('PASS stdlib-only framing/error/origin/DNS-policy/transport-audit/readiness-negative/bounded-parent-cleanup/TERM-zero-exit-rejection/UDP-source-chain-phase-result-lifetime-sanitization-and-bounds/contrast/PNG-header/argument self-tests; no Chrome, application, screenshot or network used');
}
async function main() {
  assert([22, 24].includes(Number(process.versions.node.split('.')[0])), 'requested QA requires reviewed Node 22 or 24');
  const args=argumentsMap(process.argv.slice(2)), out=path.resolve(args['--out']), profile=path.resolve(args['--profile']);
  assert.notEqual(out, profile, 'profile must not enter artifacts');
  const fixture=JSON.parse(await readFile(args['--fixture'], 'utf8'));
  assert.equal(fixture.synthetic, true);
  assert(Array.isArray(fixture.cases)&&fixture.cases.length<=20);
  assert.deepEqual([...fixture.cases.map(c=>c.name)].sort(), ['overview', 'assets', 'asset-detail', 'findings', 'finding-detail', 'integrations', 'legacy-dashboard', 'legacy-detail', 'legacy-logs', 'legacy-settings', 'legacy-reports', 'empty-assets', 'empty-findings', 'empty-integrations', 'partial-overview', 'invalid-asset'].sort(), 'required QA case matrix changed');
  const origins=new Set(Object.values(fixture.origins));
  assert.equal(origins.size, 3);
  for(const raw of origins) {
    const u=new URL(raw);
    assert.equal(u.protocol, 'http:');
    assert.equal(u.hostname, '127.0.0.1');
    assert(u.port);
    assert.equal(u.pathname, '/');
  }
  checkCaptureBudget(fixture.cases);
  const checks= {
    synthetic:true, automated_status:'running', visual_review:'pending', cases:[], flows:[], violations:[], fonts:[], navigation_events:[], fetch_decision_cancellations:[], blocked_browser_activity: {
      proxy_requests:0, proxy_connects:0, targets:[], attempts:[]
    }, reduced_motion_scope:'media preference override verified only; CSS response not exhaustively measured', screenshot_scope:'29 viewport-only PNGs (original 28 plus mobile reports); below-fold content is not fully captured', metadata:fixture.metadata
  }, manifest= {
    synthetic:true, visual_review:'pending', metadata:fixture.metadata, as_of:fixture.as_of, images:[]
  };
  let chromeStartedAt, startupDiagnostics;
  let imageBytes=0, chrome, client, proxy, watchdog, chromeStderrBytes=0, fatal, exitCode, exitSignal, spawnError, proxyOrigin;
  let chromeParentCleanup= {
    parent_exit_observed:false, descendants:'unknown; see stability.json'
  };
  const netlog=path.join(profile, 'network.json'), sessions=new Map(), requests=new Map(), documents=new Map(), allRequests=[];
  const chromeRunning=()=>!!chrome&&!spawnError&&chrome.exitCode===null&&chrome.signalCode===null;
  const violation=text=> {
    if(checks.violations.length<32)checks.violations.push(String(text).slice(0, 512));
  };
  const fetchDecisions=new FetchDecisions((error,metadata)=>{
    violation(error.message);
    checks.fetch_decision_failures??=[];
    if(checks.fetch_decision_failures.length<16)checks.fetch_decision_failures.push({
      ...metadata,error:scrubNetworkText(error.message).slice(0,512)
    });
  },metadata=>{
    if(checks.fetch_decision_cancellations.length<16)checks.fetch_decision_cancellations.push({
      ...metadata,reason:'stale_safe_interception'
    });
  });
  async function writeJSON(name, value) {
    const bytes=Buffer.from(JSON.stringify(value, null, 2)+'\n');
    assert(bytes.length<=256*1024, 'JSON evidence too large');
    await writeFile(path.join(out, name), bytes, {
      mode:0o600
    });
  }
  async function ev(session, expression) {
    const r=await client.call('Runtime.evaluate', {
      expression, returnByValue:true, awaitPromise:true
    }, session);
    if(r.exceptionDetails)throw new Error(`runtime evaluation failed: ${r.exceptionDetails.text}`);
    return r.result?.value;
  }
  async function until(session, expression, label) {
    const deadline=Date.now()+10000;
    while(Date.now()<deadline) {
      if(await ev(session, expression))return;
      await delay(40);
    }
    throw new Error(`real browser readiness timeout: ${label}`);
  }
  async function ready(session, url) {
    await until(session, `document.readyState==='complete'&&location.href===${JSON.stringify(url)}`, 'navigation');
    await ev(session, "(async()=>{await document.fonts.ready;await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));return true})()");
  }
  async function reload(session, url) {
    await fetchDecisions.drain();
    const prior=documents.get(session)?.loader;
    await client.call('Page.reload', {}, session);
    const deadline=Date.now()+10000;
    while(documents.get(session)?.loader===prior&&Date.now()<deadline)await delay(40);
    assert(documents.get(session)?.loader&&documents.get(session).loader!==prior, 'reload did not produce a new actual document');
    await ready(session, url);
  }
  async function navigate(session, url, status=200) {
    assert(allowedOrigin(url, origins), 'navigation escaped loopback');
    await fetchDecisions.drain();
    navigationDiagnostic(checks.navigation_events,'navigate-start',{url,status});
    const r=await client.call('Page.navigate', {
      url
    }, session);
    navigationDiagnostic(checks.navigation_events,'navigate-result',{url,error:r.errorText});
    assert(!r.errorText, `navigation error ${r.errorText}`);
    await ready(session, url);
    assert.equal(documents.get(session)?.status, status, `actual HTTP status for ${new URL(url).pathname}`);
    navigationDiagnostic(checks.navigation_events,'navigate-ready',{url,status});
  }
  async function key(session, key, code, number, modifiers=0) {
    if(key==='Enter')await fetchDecisions.drain();
    for(const type of ['keyDown', 'keyUp'])await client.call('Input.dispatchKeyEvent', {
      type, key, code, windowsVirtualKeyCode:number, nativeVirtualKeyCode:number, modifiers, ...(key==='Enter'&&type==='keyDown'? {
        text:'\r', unmodifiedText:'\r'
      }
      : {})
    }, session);
  }
  async function follow(session, selector) {
    const href=await ev(session, `(()=>{const el=document.querySelector(${JSON.stringify(selector)});if(!el)throw Error('missing keyboard link');el.focus();return el.href})()`);
    assert(allowedOrigin(href, origins));
    await key(session, 'Enter', 'Enter', 13);
    await ready(session, href);
    return href;
  }
  async function snapshot(session, name, viewport, caseInfo) {
    const r=await client.call('Page.captureScreenshot', {
      format:'png', fromSurface:true, captureBeyondViewport:false
    }, session);
    const data=Buffer.from(r.data, 'base64');
    assert(data.length<=MAX_PNG, 'PNG exceeds 512 KiB bound');
    assert(imageBytes+data.length<=IMAGE_BUDGET, 'PNG total exceeds 7 MiB bound');
    const dimensions=pngSize(data);
    assert.deepEqual(dimensions, {
      width:viewport.width, height:viewport.height
    });
    const file=`${name}.${viewport.name}.png`;
    assert(/^[a-z-]+\.(desktop|mobile)\.png$/.test(file));
    await writeFile(path.join(out, file), data, {
      mode:0o600
    });
    imageBytes+=data.length;
    manifest.images.push( {
      file, bytes:data.length, sha256:sha256(data), ...dimensions, viewport: {
        ...viewport
      }, case:caseInfo.name, path:caseInfo.path, origin:caseInfo.origin, status:caseInfo.status, actual_cdp:true
    });
  }
  async function platformFonts(session, caseInfo) {
    const doc=await client.call('DOM.getDocument', {}, session);
    const found=await client.call('DOM.querySelector', {
      nodeId:doc.root.nodeId, selector:'h1'
    }, session);
    if(!found.nodeId)return[];
    const value=await client.call('CSS.getPlatformFontsForNode', {
      nodeId:found.nodeId
    }, session);
    const text=await ev(session, "document.querySelector('h1')?.textContent??''");
    const fonts=value.fonts??[];
    checks.fonts.push( {
      case:caseInfo.name, heading:text.slice(0, 128), fonts
    });
    if(/[\u3040-\u30ff\u3400-\u9fff]/u.test(text))assert(fonts.some(f=>/(Noto.*(CJK|JP)|Hiragino|Yu Gothic|IPA|WenQuanYi|Droid Sans Fallback|Takao|Source Han|HanaMin)/i.test(f.familyName)), 'Japanese glyph font coverage unverified; inspect retained PNG, do not install fonts');
    return fonts;
  }
  async function inspect(session, info, viewport, start) {
    if(info.name==='legacy-settings')await until(session, CODEX_READY, 'synthetic Codex status');
    if(info.name==='legacy-logs')await until(session, "document.querySelector('#stream-status')?.textContent.includes('ライブ')", 'actual log SSE');
    const data=await ev(session, `(()=>{const main=document.querySelector('main'),ids=[...document.querySelectorAll('[id]')].map(n=>n.id),labels=[...document.querySelectorAll('label')],refs=[...document.querySelectorAll('[aria-labelledby],[aria-describedby]')].flatMap(n=>((n.getAttribute('aria-labelledby')||'')+' '+(n.getAttribute('aria-describedby')||'')).trim().split(/\\s+/).filter(Boolean));return {text:document.body.innerText.slice(0,40000),duplicateIds:ids.filter((id,i)=>ids.indexOf(id)!==i),unboundLabels:labels.filter(n=>!n.control).map(n=>n.textContent.slice(0,80)),missingRefs:refs.filter(id=>!document.getElementById(id)),current:[...document.querySelectorAll('.finding-nav [aria-current="page"]')].map(n=>n.getAttribute('href')),overflow:main?main.scrollWidth>main.clientWidth+1:true,unsafeLinks:[...document.querySelectorAll('a[href]')].filter(n=>!n.href.startsWith(location.origin+'/')&&!n.href.startsWith(location.origin+'#')).map(n=>n.getAttribute('href')).slice(0,8),injected:window.__qa_injected===true,rich:!![...document.querySelectorAll('.markdown-body strong')].find(n=>n.textContent.includes('Synthetic browser Markdown')),reduced:matchMedia('(prefers-reduced-motion: reduce)').matches}})()`);
    const observed=(requests.get(session)??[]).slice(start), sse=observed.some(r=>new URL(r.url).pathname==='/api/logs-stream');
    checks.cases.push( {
      name:info.name, viewport:viewport.name, status:documents.get(session)?.status, duplicate_ids:data.duplicateIds, unbound_labels:data.unboundLabels, missing_aria:data.missingRefs, main_overflow:data.overflow, sse, rich:data.rich, legacy_label_scope:info.native?'enforced':'reported; existing form migration is not declared complete'
    });
    if(shouldCapture(info,viewport))await snapshot(session, info.name, viewport, info);
    assert(data.text.includes(info.want), `missing expected ${info.name} content`);
    assert.equal(data.injected, false, 'synthetic untrusted text executed');
    assert.deepEqual(data.duplicateIds, [], 'duplicate DOM IDs');
    assert.deepEqual(data.missingRefs, [], 'broken ARIA reference');
    assert.equal(data.overflow, false, 'main body horizontally overflows');
    if(viewport.mobile) {
      const issues=await ev(session,`(${responsiveLayoutIssues.toString()})()`);
      checks.cases.at(-1).responsive_layout_issues=issues;
      assert.deepEqual(issues,[],'mobile labels or controls overlap');
    }
    assert(data.reduced, 'reduced-motion override absent');
    assert.deepEqual(data.current, info.nav?[info.nav]:[], 'selected navigation mismatch');
    if(info.native) {
      assert.deepEqual(data.unboundLabels, [], 'unassociated native form label');
      assert.deepEqual(data.unsafeLinks, [], 'native evidence became an external/executable URL');
      assert.equal(sse, false, 'native page opened a legacy SSE stream');
    }else {
      assert(sse, 'legacy page did not open actual log SSE');
    }
    if(info.rich)assert(data.rich, 'actual Goldmark strong markup absent');
    if(info.name==='overview')for(const [name, count]of Object.entries(fixture.metrics)) {
      const n=await ev(session, `[...document.querySelectorAll('.console-metric')].find(n=>n.querySelector('h2')?.textContent===${JSON.stringify(name)})?.querySelector('strong')?.textContent`);
      assert.equal(Number(n), count, `retained global metric ${name}`);
    }
    if(info.name==='integrations')for(const word of ['failed', 'running', 'partial', 'unknown', 'epss_offline', 'kev_offline', 'github_code_scanning', 'github_secret_scanning'])assert(data.text.includes(word), `recorded state/source missing ${word}`);
    await platformFonts(session, info);
    console.log(`PASS real browser ${viewport.name} ${info.name}`);
  }
  async function hoverContrast(session, selector, label) {
    await ev(session, `document.querySelector(${JSON.stringify(selector)}).scrollIntoView({block:'center'})`);
    const p=await ev(session, `(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await client.call('Input.dispatchMouseEvent', {
      type:'mouseMoved', x:p.x, y:p.y
    }, session);
    assert(await ev(session, `document.querySelector(${JSON.stringify(selector)}).matches(':hover')`), `${label} did not enter actual :hover`);
    const colors=await ev(session, `(()=>{const s=getComputedStyle(document.querySelector(${JSON.stringify(selector)}));return{fg:s.color,bg:s.backgroundColor}})()`);
    const ratio=contrast(colors.fg, colors.bg);
    checks.flows.push( {
      check:label, hover_matched:true, ratio, colors
    });
    assert(ratio>=4.5, `${label} hover contrast below 4.5:1`);
  }
  async function flows(session, viewport) {
    const base=fixture.origins.primary;
    await navigate(session, base+'/assets');
    await key(session, 'Tab', 'Tab', 9);
    assert(await ev(session, "document.activeElement.classList.contains('finding-skip')"), 'first Tab did not reach skip link');
    const initialFocus=await ev(session,`(${skipFocusState.toString()})()`);
    // Observe rendering after input dispatch; this does not assume a cause.
    // Observe two rendering frames without changing focus, styles or scroll.
    await ev(session,'new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
    assert(await ev(session, "document.activeElement.classList.contains('finding-skip')"), 'skip focus changed during rendering observation');
    const focus=await ev(session,`(${skipFocusState.toString()})()`);
    checks.flows.push({check:'skip-link keyboard focus',viewport:viewport.name,initial:initialFocus,...focus});
    assert(focus.style!=='none'&&focus.width>=2&&focus.visible, 'keyboard focus is not visible');
    await key(session, 'Tab', 'Tab', 9);
    await key(session, 'Tab', 'Tab', 9, 8);
    assert(await ev(session, "document.activeElement.classList.contains('finding-skip')"), 'Shift-Tab lost skip link');
    await key(session, 'Enter', 'Enter', 13);
    assert(await ev(session, "location.hash==='#main-content'"), 'skip Enter did not navigate');
    await navigate(session, base+'/assets?limit=1&source=dependabot');
    await ev(session, "document.querySelector('#asset-q').focus()");
    await client.call('Input.insertText', {
      text:'browser'
    }, session);
    await key(session, 'Enter', 'Enter', 13);
    await until(session, "document.readyState==='complete'&&new URL(location.href).searchParams.get('q')==='browser'", 'keyboard filter submission');
    await hoverContrast(session, '.btn-primary', 'native primary');
    const next=await follow(session, 'a[rel="next"]');
    assert.equal(new URL(next).searchParams.get('source'), 'dependabot');
    const selected=await follow(session, '.console-table tbody td:first-child a');
    assert(new URL(selected).pathname.startsWith('/assets/'));
    let history=await client.call('Page.getNavigationHistory', {}, session);
    assert(history.currentIndex>0);
    await fetchDecisions.drain();
    await client.call('Page.navigateToHistoryEntry', {
      entryId:history.entries[history.currentIndex-1].id
    }, session);
    await ready(session, next);
    await reload(session, next);
    assert.equal(await ev(session, "new URL(location.href).searchParams.get('q')"), 'browser');
    history=await client.call('Page.getNavigationHistory', {}, session);
    assert(history.currentIndex+1<history.entries.length);
    await fetchDecisions.drain();
    await client.call('Page.navigateToHistoryEntry', {
      entryId:history.entries[history.currentIndex+1].id
    }, session);
    await ready(session, selected);
    const back=await follow(session, '.finding-topline a');
    assert.equal(new URL(back).searchParams.get('q'), 'browser');
    assert.equal(new URL(back).searchParams.get('source'), 'dependabot');
    await navigate(session, base+fixture.long_asset_url);
    const longBack=await follow(session, '.finding-topline a');
    assert.equal(Buffer.byteLength(new URL(longBack).searchParams.get('q')), 256);
    await reload(session, longBack);
    await navigate(session, base+fixture.cleared_source_url);
    const cleared=await ev(session, `(()=>{const link=[...document.querySelectorAll('a')].find(a=>a.getAttribute('href')?.startsWith('/findings?asset_id='));return{all:link?!new URL(link.href).searchParams.has('source'):false,anchor:!!document.querySelector('a[href="/findings/${fixture.anchor_id}"]')}})()`);
    assert(cleared.all&&cleared.anchor, 'cleared source inherited return-list source');
    // Leave both legacy log streams, then restore the page through real browser
    // history. This covers history-cached documents as well as fresh reloads.
    await navigate(session, base+'/logs');
    await until(session, "document.querySelector('#stream-status')?.textContent.includes('ライブ')", 'legacy stream before history');
    const logRequests=()=> (requests.get(session)??[]).filter(r=>new URL(r.url).pathname==='/api/logs-stream').length;
    const beforeRestore=logRequests();
    await navigate(session, base+'/assets');
    const legacyHistory=await client.call('Page.getNavigationHistory', {}, session);
    assert(legacyHistory.currentIndex>0);
    await fetchDecisions.drain();
    await client.call('Page.navigateToHistoryEntry', {
      entryId:legacyHistory.entries[legacyHistory.currentIndex-1].id
    }, session);
    await ready(session, base+'/logs');
    await until(session, "document.querySelector('#stream-status')?.textContent.includes('ライブ')", 'legacy stream after history');
    assert(logRequests()>beforeRestore, 'restored legacy page did not reconnect actual SSE');
    await reload(session, base+'/logs');
    await until(session, "document.querySelector('#stream-status')?.textContent.includes('ライブ')", 'legacy stream after reload');
    checks.flows.push({check:'actual legacy SSE navigation/history restoration/reload',viewport:viewport.name,passed:true});
    await navigate(session, base+'/');
    // Dashboard action buttons live in initially closed native <details>.
    // Reveal via the actual summary keyboard action, never click a POST button.
    if(await ev(session, `(${focusLegacyDangerDisclosure.toString()})()`)) {
      await key(session, 'Enter', 'Enter', 13);
      await until(session, "document.querySelector('.btn-reject')?.closest('details')?.open===true", 'legacy action disclosure');
    }
    await hoverContrast(session, '.btn-reject', 'legacy danger');
    checks.flows.push( {
      check:'actual keyboard/filter/paging/Back/Forward/reload/long-query/cleared-source', viewport:viewport.name, passed:true
    });
  }
  try {
    await mkdir(profile, {
      recursive:false, mode:0o700
    });
    // A rejecting loopback proxy gives browser background traffic no external
    // destination, including literal IPs. It never forwards. Blocked internal
    // startup attempts are separate from any permitted/page/external transport.
    proxy=createServer((req, res)=> {
      checks.blocked_browser_activity.proxy_requests++;
      if(checks.blocked_browser_activity.attempts.length<16)checks.blocked_browser_activity.attempts.push(networkLabel(req.url));
      if(allowedOrigin(req.url, origins))violation('fixture request unexpectedly reached deny proxy');
      res.writeHead(403);
      res.end('offline synthetic QA');
    });
    proxy.on('connect', (req, socket)=> {
      checks.blocked_browser_activity.proxy_connects++;
      if(checks.blocked_browser_activity.attempts.length<16)checks.blocked_browser_activity.attempts.push(networkLabel('https://'+req.url));
      socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    });
    proxy.listen(0, '127.0.0.1');
    await once(proxy, 'listening');
    proxyOrigin=`http://127.0.0.1:${proxy.address().port}`;
    const policy=networkPolicy(origins, proxyOrigin);
    const flags=['--headless=new', '--remote-debugging-pipe', `--user-data-dir=${profile}`, '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps', '--disable-extensions', '--disable-breakpad', '--disable-quic', '--no-first-run', '--no-default-browser-check', `--proxy-server=http://127.0.0.1:${proxy.address().port}`, `--proxy-bypass-list=${policy.bypass}`, `--host-resolver-rules=${policy.resolver}`, `--log-net-log=${netlog}`, '--net-log-capture-mode=Default', 'about:blank'];
    assert(!flags.some(s=>/^--(no-sandbox|disable-setuid-sandbox|disable-web-security|ignore-certificate-errors)/.test(s)), 'unsafe browser flag');
    const chromeEnv=Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL'].filter(k=>process.env[k]!==undefined).map(k=>[k, process.env[k]]));
    chromeStartedAt=performance.now();
    try {startupDiagnostics=createStartupDiagnostics(process.version, chromeStartedAt, ()=>performance.now());}catch { /* Diagnostics cannot block the existing spawn. */ }
    checks.startup={chrome_binary:path.basename(args['--chrome']),cdp_command_timeout_ms:10000};
    chrome=spawn(args['--chrome'], flags, {
      stdio:['ignore', 'ignore', 'pipe', 'pipe', 'pipe'], env:chromeEnv
    });
    chrome.stderr.on('data', b=> {
      chromeStderrBytes+=b.length;
      startupObserve(startupDiagnostics, 'stderr', b);
    });
    client=new CDP(chrome.stdio[3], chrome.stdio[4], startupDiagnostics);
    chrome.once('spawn', ()=>startupObserve(startupDiagnostics, 'spawn'));
    chrome.once('close', ()=>startupObserve(startupDiagnostics, 'close'));
    chrome.on('error', e=> {
      startupObserve(startupDiagnostics, 'childError', e);
      spawnError=e;
      client.close(e, 'child_error');
    });
    chrome.on('exit', (code, signal)=> {
      exitCode=code;
      exitSignal=signal;
      startupObserve(startupDiagnostics, 'exit');
      client.close(new Error(`Chrome exited ${code}`), 'child_exit');
    });
    watchdog=setTimeout(()=> {
      violation('browser QA real-time watchdog');
      chrome.kill('SIGTERM');
      setTimeout(()=> {
        if(chromeRunning())chrome.kill('SIGKILL');
      }, 2000).unref();
    }, 180000);
    const stop=()=> {
      violation('browser QA interrupted');
      chrome.kill('SIGTERM');
    };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    client.listeners.push(message=> {
      if(message.method==='Target.attachedToTarget') {
        const {
          sessionId, targetInfo
        }
        =message.params;
        navigationDiagnostic(checks.navigation_events,'target-attached',{
          url:targetInfo.url,type:targetInfo.type,waiting:message.params.waitingForDebugger===true
        });
        const configure=(async()=> {
          assert(sessions.size<=8, 'unexpected browser target count');
          if(!['page', 'iframe'].includes(targetInfo.type)) {
            const internal=internalTarget(targetInfo);
            if(!internal)violation(`unexpected non-application target type ${targetInfo.type}`);
            if(checks.blocked_browser_activity.targets.length<16)checks.blocked_browser_activity.targets.push( {
              type:targetInfo.type, url:networkLabel(targetInfo.url), waiting_for_debugger:message.params.waitingForDebugger===true, disposition:'closed without resuming; transport audited separately'
            });
            const closed=await client.call('Target.closeTarget', {
              targetId:targetInfo.targetId
            });
            assert.equal(closed.success, true, 'quarantined target failed to close');
            return sessionId;
          }
          assert(targetInfo.url===''||targetInfo.url==='about:blank'||allowedOrigin(targetInfo.url, origins), 'unexpected page/iframe origin');
          await client.call('Network.enable', {}, sessionId);
          await client.call('Network.setBypassServiceWorker', {
            bypass:true
          }, sessionId);
          await client.call('Network.setBlockedURLs', {
            urls:['ws://*', 'wss://*']
          }, sessionId);
          await client.call('Fetch.enable', {
            patterns:[ {
              urlPattern:'*'
            }]
          }, sessionId);
          await client.call('Runtime.enable', {}, sessionId);
          await client.call('Page.enable', {}, sessionId);
          await client.call('DOM.enable', {}, sessionId);
          await client.call('CSS.enable', {}, sessionId);
          await client.call('Target.setAutoAttach', {
            autoAttach:true, waitForDebuggerOnStart:true, flatten:true
          }, sessionId);
          await client.call('Runtime.runIfWaitingForDebugger', {}, sessionId);
          return sessionId;
        })();
        sessions.set(targetInfo.targetId, configure);
        configure.catch(e=>{
          navigationDiagnostic(checks.navigation_events,'target-configure-failed',{error:e.message});
          violation(e.message);
        });
      }else if(message.method==='Fetch.requestPaused') {
        const {
          requestId, request
        }
        =message.params;
        if(message.params.resourceType==='Document')navigationDiagnostic(checks.navigation_events,'document-paused',{
          url:request.url,status:message.params.responseStatusCode,error:message.params.responseErrorReason
        });
        const fixtureOrigin=allowedOrigin(request.url, origins);
        const safe=(request.url==='about:blank'||fixtureOrigin)&&['GET', 'HEAD'].includes(request.method);
        if(!safe)violation(`blocked off-origin/action page request ${request.method} ${networkLabel(request.url)}`);
        fetchDecisions.track(()=>client.call(safe?'Fetch.continueRequest':'Fetch.failRequest', safe? {
          requestId
        }
        : {
          requestId, errorReason:'BlockedByClient'
        }, message.sessionId).then(()=>{
          if(message.params.resourceType==='Document')navigationDiagnostic(checks.navigation_events,safe?'document-continued':'document-blocked',{url:request.url});
        }),{
          safe,fixture_origin:fixtureOrigin,method:['GET','HEAD'].includes(request.method)?request.method:'other',
          resource_type:['Document','Stylesheet','Image','Media','Font','Script','TextTrack','XHR','Fetch','Prefetch','EventSource','WebSocket','Manifest','SignedExchange','Ping','CSPViolationReport','Preflight','Other'].includes(message.params.resourceType)?message.params.resourceType:'unknown',
          session:sha256(String(message.sessionId)).slice(0,16),
          interception:sha256(String(requestId)).slice(0,16),
          network_request:message.params.networkId?sha256(String(message.params.networkId)).slice(0,16):null,
          url:networkLabel(request.url).slice(0,256),
          response_stage:isFetchResponseStage(message.params)
        });
      }else if(message.method==='Network.requestWillBeSent') {
        const request=message.params.request;
        if(request.url==='about:blank')return;
        if(!allowedOrigin(request.url, origins))violation(`non-loopback page request ${networkLabel(request.url)}`);
        const list=requests.get(message.sessionId)??[];
        if(list.length<512)list.push( {
          url:request.url, method:request.method
        });
        else violation('request bound exceeded');
        requests.set(message.sessionId, list);
        if(allRequests.length<1024)allRequests.push(request.url);
      }else if(message.method==='Network.responseReceived'&&message.params.type==='Document') {
        navigationDiagnostic(checks.navigation_events,'document-response',{
          url:message.params.response.url,status:message.params.response.status
        });
        documents.set(message.sessionId, {
          url:message.params.response.url, status:message.params.response.status, loader:message.params.loaderId
        });
      } else if(message.method==='Network.loadingFailed'&&message.params.type==='Document') {
        navigationDiagnostic(checks.navigation_events,'document-failed',{error:message.params.errorText});
      } else if(message.method==='Page.frameNavigated'&&!message.params.frame.parentId) {
        navigationDiagnostic(checks.navigation_events,'frame-navigated',{url:message.params.frame.url});
      } else if(message.method==='Page.javascriptDialogOpening') {
        navigationDiagnostic(checks.navigation_events,'unexpected-dialog',{url:message.params.url,type:message.params.type});
        violation('unexpected JavaScript dialog blocks browser acceptance');
      } else if(message.method==='Network.webSocketCreated') {
        violation('unexpected WebSocket');
      }
    });
    checks.browser=await client.call('Browser.getVersion');
    checks.startup.handshake_elapsed_ms=Math.round(performance.now()-chromeStartedAt);
    checks.cdp_pipe_handshake=true;
    manifest.browser=checks.browser;
    checks.node=process.version;
    checks.network_guard='exact fixture origins/ports; implicit loopback bypass removed; rejecting loopback proxy; no DIRECT fallback; all other DNS denied';
    checks.network_policy= {
      resolver:policy.resolver, bypass:policy.bypass
    };
    checks.sandbox_disable_flags=false;
    checks.configured_deadlines_ms= {
      cdp_command:10000, navigation:10000, browser_watchdog:180000, graceful_exit:3000, signal_exit:2000
    };
    manifest.node=process.version;
    await client.call('Target.setAutoAttach', {
      autoAttach:true, waitForDebuggerOnStart:true, flatten:true
    });
    for(const viewport of [ {
      name:'desktop', width:1440, height:1000, mobile:false
    }, {
      name:'mobile', width:390, height:844, mobile:true
    }]) {
      const {
        targetId
      }
      =await client.call('Target.createTarget', {
        url:'about:blank'
      });
      const deadline=Date.now()+10000;
      while(!sessions.has(targetId)&&Date.now()<deadline)await delay(20);
      assert(sessions.has(targetId), 'CDP auto-attach handshake failed');
      const session=await sessions.get(targetId);
      await client.call('Target.activateTarget', {
        targetId
      });
      await client.call('Emulation.setDeviceMetricsOverride', {
        width:viewport.width, height:viewport.height, screenWidth:viewport.width, screenHeight:viewport.height, mobile:viewport.mobile, deviceScaleFactor:1
      }, session);
      await client.call('Emulation.setEmulatedMedia', {
        features:[ {
          name:'prefers-reduced-motion', value:'reduce'
        }]
      }, session);
      await client.call('Emulation.setFocusEmulationEnabled', {
        enabled:true
      }, session);
      for(const info of fixture.cases) {
        const start=(requests.get(session)??[]).length;
        await navigate(session, new URL(info.path, fixture.origins[info.origin]).href, info.status);
        await inspect(session, info, viewport, start);
        assert.equal(checks.violations.length, 0, 'offline/browser guard violation');
      }
      await flows(session, viewport);
      await fetchDecisions.drain();
      await client.call('Target.closeTarget', {
        targetId
      });
    }
  }catch(e) {
    fatal=e;
    if(!checks.cdp_pipe_handshake&&chromeStartedAt!==undefined)checks.startup={
      ...checks.startup,failed_after_ms:Math.round(performance.now()-chromeStartedAt),
      received_bytes:client?.receivedBytes??0,received_messages:client?.receivedMessages??0,
      buffered_bytes:client?.buffer.length??0,sent_commands:client?.next??0,
      chrome_stderr_bytes:chromeStderrBytes
    };
    startupObserve(startupDiagnostics, 'failure', client);
    checks.error=scrubNetworkText(e.stack??e).slice(0, 16384);
    // Preserve decisive bounded evidence in the job log even after artifacts expire.
    console.error('FAIL browser navigation diagnostics',JSON.stringify({
      error:checks.error,startup:checks.startup,events:checks.navigation_events,violations:checks.violations
    }));
  } finally {
    clearTimeout(watchdog);
    startupObserve(startupDiagnostics, 'cleanup', chrome, spawnError);
    if(chrome&&!spawnError) {
      try { await fetchDecisions.drain(); } catch(e) { violation(e.message); }
      chromeParentCleanup=await stopChromeParent(chrome, async()=> {
        try {
          if(!client)startupObserve(startupDiagnostics, 'notSent', 'Browser.close', 'client_absent');
          await client?.call('Browser.close');
        }catch {
          /* Parent exit and Go supervisor determine cleanup, never this exception. */
        }
      });
      startupObserve(startupDiagnostics, 'parentStopped');
      const cleanupProblem=chromeParentCleanupFailure(chromeParentCleanup);
      if(cleanupProblem)violation(cleanupProblem);
      try {
        assert((await stat(netlog)).size<=16*1024*1024, 'NetLog file exceeds audit bound');
        const log=JSON.parse(await readFile(netlog, 'utf8'));
        startupObserve(startupDiagnostics, 'netlog', log);
        const report=netlogAudit(log, origins, networkPolicy(origins, proxyOrigin).endpoints);
        checks.network_audit=report;
        for(const problem of report.violations)violation(problem);
      }catch(e) {
        checks.network_audit={status:'unknown',error_code:e.code??e.name};
        violation('network audit unavailable/invalid; transport outcome unknown');
      }
    }
    if(proxy) {
      proxy.closeAllConnections();
      await new Promise(resolve=>proxy.close(resolve));
    }
    checks.chrome_stderr_summary={observed_bytes:chromeStderrBytes,raw_retained:false};
    checks.chrome_exit_code=exitCode??null;
    checks.chrome_exit_signal=exitSignal??null;
    checks.chrome_parent_cleanup=chromeParentCleanup;
    checks.chrome_descendant_cleanup='unknown in Node; authoritative Linux group/adopted-PID verification is in stability.json';
    checks.loopback_proxy_closed=!!proxy;
    if(chrome&&!spawnError&&exitCode!==0)violation(`Chrome exited abnormally: ${exitCode}/${exitSignal}`);
    checks.request_count=allRequests.length;
    checks.automated_status=!fatal&&checks.violations.length===0?'passed':'failed';
    checks.visual_review='pending';
    fitTCPDiagnosticBudget(checks);
    // Legacy TCP projection and JSON-size failure take precedence over startup detail.
    fitStartupDiagnosticBudget(checks, startupDiagnostics, client);
    await writeJSON('checks.json', checks);
    manifest.automated_status=checks.automated_status;
    manifest.configured_deadlines_ms=checks.configured_deadlines_ms?? {};
    manifest.child_cleanup= {
      chrome_exit_code:checks.chrome_exit_code, chrome_exit_signal:checks.chrome_exit_signal, parent:chromeParentCleanup, descendants:checks.chrome_descendant_cleanup, loopback_proxy_closed:checks.loopback_proxy_closed
    };
    manifest.screenshot_scope=checks.screenshot_scope;
    manifest.reduced_motion_scope=checks.reduced_motion_scope;
    await writeJSON('manifest.json', manifest);
    const files=await readdir(out);
    assert(files.length<=31, 'artifact file count exceeds Node budget');
    let bytes=0;
    for(const f of files) {
      assert(/^[a-z-]+\.(desktop|mobile)\.png$/.test(f)||['manifest.json', 'checks.json'].includes(f), 'unexpected artifact entry');
      const s=await stat(path.join(out, f));
      assert(s.isFile());
      bytes+=s.size;
    }
    assert(bytes<=8*1024*1024, 'artifact size exceeds bound');
  }
  if(fatal)throw fatal;
  assert.equal(checks.cases.length, fixture.cases.length*2, 'incomplete desktop/mobile matrix');
  assert.equal(manifest.images.length, 29, 'incomplete runtime screenshot matrix');
  assert.equal(checks.violations.length, 0, `offline guard failed: ${checks.violations.join('; ')}`);
  assert.equal(checks.automated_status, 'passed');
  console.log(`PASS automated real Chrome checks; ${manifest.images.length} runtime PNGs saved. Download/materialization/visual review remain pending.`);
}
if(process.argv.slice(2).length===1&&process.argv[2]==='--self-test')await selfTest();
else await main();
