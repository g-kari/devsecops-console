import {createStartupReceiptArena} from './browser_startup_diagnostics.mjs';
// Fixed one-hop capture projection. No I/O, timers, control, raw text or verdict.
// Exactly 12736 backing bytes, two views. This is NOT a V8 heap bound.
const KEY='tcp_lifecycle_diagnostics',NIL=0xffffffff,G=2048,C=2080,S=2144;
const EVENT_NAMES=Object.freeze(['CONNECT_JOB','TRANSPORT_CONNECT_JOB_CONNECT','TCP_CONNECT_JOB_CONNECT','CONNECT_JOB_TIMED_OUT','TRANSPORT_CONNECT_JOB_CONNECT_ATTEMPT','TCP_CONNECT_JOB_CONNECTOR_CONNECT_START','TCP_CONNECT_JOB_CONNECTOR_CONNECT_COMPLETE','TCP_CONNECT_JOB_CONNECTOR_DONE','TCP_STREAM_ATTEMPT_ALIVE','TCP_STREAM_ATTEMPT_CONNECT','TLS_STREAM_ATTEMPT_ALIVE','TLS_STREAM_ATTEMPT_CONNECT','CONNECT_JOB_SET_SOCKET','SOCKET_POOL_BOUND_TO_SOCKET','TCP_CONNECT','TCP_CONNECT_ATTEMPT','SOCKET_BYTES_SENT','SOCKET_ALIVE']);
const SOURCE_NAMES=Object.freeze(['SOCKET','HTTP_PROXY_CONNECT_JOB','SOCKS_CONNECT_JOB','SSL_CONNECT_JOB','TRANSPORT_CONNECT_JOB','TCP_CONNECT_JOB','TCP_STREAM_ATTEMPT','TLS_STREAM_ATTEMPT','HTTP_STREAM_JOB','HTTP_STREAM_POOL_ATTEMPT_MANAGER']);
const SOURCE_CODES=Object.freeze([10,3,4,5,6,7,8,9,17,21]);
const CANCEL=Object.freeze(['Unspecified','CloseAllConnections','IpAddressChanged','SslConfigChanged','CannotUseTcpBasedProtocols','SpdySessionCreated','QuicSessionCreated','UsingExistingSpdySession','UsingExistingQuicSession','Abort','AttemptManagerDraining']);
const ROOT_KEYS=Object.freeze(['schema_version','status','pending_keys','selected_sources','shown_sources','unselected_keys','trimmed_sources','trimmed_keys','flags','records']);
const ABSENT=Symbol('absent'),BAD=Symbol('invalid');
const integer=(x,min,max)=>typeof x==='number'&&Number.isInteger(x)&&!Object.is(x,-0)&&x>=min&&x<=max;
const numericInteger=(x,min,max)=>typeof x==='number'&&Number.isInteger(x)&&x>=min&&x<=max;
const digits=x=>x<10?1:x<100?2:x<1000?3:x<10000?4:5;
const code=x=>integer(x,0,2147483647);
const id=x=>integer(x,-2147483648,2147483647)&&x!==0;
function plain(x){return x!==null&&typeof x==='object'&&(Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);}
function own(x,key){
  if(!plain(x))return BAD;
  const d=Object.getOwnPropertyDescriptor(x,key);
  return !d?ABSENT:Object.hasOwn(d,'value')?d.value:BAD;
}
function arrayLength(x){
  if(!Array.isArray(x)||Object.getPrototypeOf(x)!==Array.prototype)throw 0;
  const d=Object.getOwnPropertyDescriptor(x,'length');
  if(!d||!Object.hasOwn(d,'value')||!integer(d.value,0,100000))throw 0;
  return d.value;
}
function at(x,i){const d=Object.getOwnPropertyDescriptor(x,i);if(!d||!Object.hasOwn(d,'value'))throw 0;return d.value;}
const signed=x=>x>2147483647?x-4294967296:x;
const encoded=x=>x<0?x+4294967296:x;
const nullable=x=>x===NIL?null:x;
const relative=x=>x===NIL?null:x-300000;
function kind(type){for(let i=0;i<10;i++)if(type===SOURCE_CODES[i])return i+1;return 0;}
// Parse canonical signed int64 into caller-owned three words, no BigInt/coercion.
function tick(w,value,p=S){
  if(typeof value!=='string'||value.length<1||value.length>20)return false;
  let sign=value[0]==='-'?1:0,i=sign,hi=0,lo=0;
  if(i===value.length||value[i]==='0'&&(value.length-i!==1||sign))return false;
  for(;i<value.length;i++){
    const d=value.charCodeAt(i)-48;if(d<0||d>9)return false;
    const n=lo*10+d,carry=Math.floor(n/4294967296);lo=n-carry*4294967296;hi=hi*10+carry;
    if(hi>2147483648)return false;
  }
  if(hi>2147483647+(sign?1:0)||hi===2147483648&&lo!==0)return false;
  w[p]=hi;w[p+1]=lo;w[p+2]=sign;return true;
}
function delta(w,a,b,min){
  const ah=w[a],al=w[a+1],as=w[a+2],bh=w[b],bl=w[b+1],bs=w[b+2];
  let hi,lo,negative;
  if(as!==bs){const n=al+bl;lo=n%4294967296;hi=ah+bh+Math.floor(n/4294967296);negative=!!as;}
  else {
    const less=ah<bh||ah===bh&&al<bl;
    const xh=less?bh:ah,xl=less?bl:al,yh=less?ah:bh,yl=less?al:bl;
    lo=xl-yl;hi=xh-yh;if(lo<0){lo+=4294967296;hi--;}
    negative=as?!less:less;
  }
  if(hi!==0||lo>300000)return NIL;
  const n=negative&&lo?-lo:lo;return n<min?NIL:n+300000;
}
function accumulate(w,h,source,controller){
  const base=controller?19:3,start=controller?21:4,bits=controller?61:62;
  let state=w[h+bits];const type=own(source,'type'),time=own(source,'start_time');
  if(type===ABSENT)state|=4;
  else if(!code(type))state|=16;
  else {if(state&1){if(w[h+base]!==type)state|=64;}else w[h+base]=type;state|=1;}
  if(time===ABSENT)state|=8;
  else if(!tick(w,time))state|=32;
  else {if(state&2){if(w[h+start]!==w[S]||w[h+start+1]!==w[S+1]||w[h+start+2]!==w[S+2])state|=128;}
    else {w[h+start]=w[S];w[h+start+1]=w[S+1];w[h+start+2]=w[S+2];}state|=2;}
  w[h+bits]=state;
}
function identity(bits){return bits&192?3:bits&48?2:bits&12?1:(bits&3)===3?0:1;}
const EMPTY=Object.freeze({});
function paramsOf(event){const p=own(event,'params');return p===ABSENT?EMPTY:p;}
function dependency(params,target){
  const dep=own(params,'source_dependency');if(dep===ABSENT)return ABSENT;
  if(!plain(dep))return BAD;
  const type=own(dep,'type'),value=own(dep,'id');
  if(!code(type)||!id(value)||value===target)return BAD;
  return dep;
}
function sameSource(event){const s=own(event,'source'),value=own(s,'id');if(!id(value))throw 0;return s;}
function phase(w,event){const value=own(event,'phase');if(!code(value))return 3;for(let i=0;i<3;i++)if(value===w[C+18+i])return i;return 3;}
function eventCode(w,event){const value=own(event,'type');if(!code(value))return 0;for(let i=0;i<18;i++)if(value===w[C+i])return i+1;return 0;}
function registry(w,log,names){
  if(Object.getPrototypeOf(names)!==Map.prototype)return false;
  const constants=own(log,'constants'),events=own(constants,'logEventTypes'),phases=own(constants,'logEventPhase'),sources=own(constants,'logSourceType'),errors=own(constants,'netError');
  for(let i=0;i<18;i++){
    const value=own(events,EVENT_NAMES[i]);if(!code(value)||Map.prototype.get.call(names,value)!==EVENT_NAMES[i])return false;
    for(let j=0;j<i;j++)if(w[C+j]===value)return false;w[C+i]=value;
  }
  const phasesNames=['PHASE_NONE','PHASE_BEGIN','PHASE_END'];
  for(let i=0;i<3;i++){const value=own(phases,phasesNames[i]);if(!code(value))return false;for(let j=0;j<i;j++)if(w[C+18+j]===value)return false;w[C+18+i]=value;}
  for(let i=0;i<10;i++){const value=own(sources,SOURCE_NAMES[i]);if(!code(value)||value!==SOURCE_CODES[i])return false;w[C+21+i]=value;}
  const errorNames=['ERR_ABORTED','ERR_TIMED_OUT','ERR_NETWORK_IO_SUSPENDED'],values=[-3,-7,-331];
  for(let i=0;i<3;i++){if(own(errors,errorNames[i])!==values[i])return false;w[C+31+i]=encoded(values[i]);}
  return true;
}
function allowedRevision(checks){
  const value=own(own(checks,'browser'),'revision');
  return value==='049750111b1e5c11565c792b2aeed5541f332bad'||value==='@049750111b1e5c11565c792b2aeed5541f332bad'||value==='4b3d0dabb8250b6f152d2d85d79e7706e309d087'||value==='@4b3d0dabb8250b6f152d2d85d79e7706e309d087';
}
function clearController(w,h,status,ident){w[h+16]=status;w[h+20]=ident;w[h+17]=0;w[h+18]=0;w[h+24]=NIL;w[h+29]=NIL;w[h+30]=0;w[h+31]=0;}
function collect(w,checks,log,pending,names){
  w[G+4]=0;w[G+5]=0;w[G+6]=NIL;w[G+7]=NIL;w[G+8]=0;
  if(Object.getPrototypeOf(pending)!==Map.prototype)throw 0;
  const size=Reflect.getOwnPropertyDescriptor(Map.prototype,'size').get.call(pending);
  if(!integer(size,0,100000))throw 0;w[G+6]=size;w[G+7]=size;
  if(!allowedRevision(checks)){w[G+4]|=2;w[G+8]=2;return;}
  if(!registry(w,log,names)){w[G+4]|=4;w[G+8]=2;return;}
  const events=own(log,'events'),length=arrayLength(events);if(size>length)throw 0;
  const anchor=length&&tick(w,own(at(events,0),'time'),S+3);w[G+9]=anchor?1:0;
  const find=value=>{for(let j=0;j<w[G+5];j++)if(signed(w[j*64])===value)return j;return -1;};
  const pendingEvent=index=>{
    if(!integer(index,0,length-1)){w[G+4]|=16;return null;}
    const event=at(events,index),source=own(event,'source'),value=own(source,'id'),ec=eventCode(w,event);
    if(!id(value)||phase(w,event)!==1||(ec!==15&&ec!==16)){w[G+4]|=16;return null;}
    return event;
  };
  // P: exactly two scans of the ORIGINAL pending Map. No key parsing/copy.
  let seen=0;
  for(const index of Map.prototype.values.call(pending)){
    if(++seen>size)throw 0;const event=pendingEvent(index);if(!event)continue;
    const value=own(own(event,'source'),'id');let slot=find(value);
    if(slot>=0){const h=slot*64;if(index<w[h+10])w[h+10]=index;continue;}
    if(w[G+5]<16)slot=w[G+5]++;
    else {slot=0;for(let j=1;j<16;j++)if(w[j*64+10]>w[slot*64+10]||w[j*64+10]===w[slot*64+10]&&signed(w[j*64])>signed(w[slot*64]))slot=j;
      if(index>w[slot*64+10]||index===w[slot*64+10]&&value>=signed(w[slot*64]))continue;}
    const h=slot*64;for(let j=0;j<64;j++)w[h+j]=0;w[h]=encoded(value);w[h+10]=index;
  }
  if(seen!==size)throw 0;
  // Sort fixed headers by earliest BEGIN, tie signed ID, using fixed scratch words.
  for(let a=0;a<w[G+5];a++)for(let b=a+1;b<w[G+5];b++)if(w[b*64+10]<w[a*64+10]||w[b*64+10]===w[a*64+10]&&signed(w[b*64])<signed(w[a*64]))for(let k=0;k<64;k++){const x=w[a*64+k];w[a*64+k]=w[b*64+k];w[b*64+k]=x;}
  for(let j=0;j<w[G+5];j++){const h=j*64;w[h+11]=0;w[h+14]=NIL;w[h+15]=NIL;w[h+7]=NIL;w[h+24]=NIL;}
  seen=0;let selectedKeys=0;
  for(const index of Map.prototype.values.call(pending)){
    if(++seen>size)throw 0;const event=pendingEvent(index);if(!event)continue;
    const source=own(event,'source'),slot=find(own(source,'id'));if(slot<0)continue;
    const h=slot*64;w[h+8]|=eventCode(w,event)===15?1:2;w[h+9]++;selectedKeys++;if(w[h+9]>2)throw 0;
    w[h+11]=Math.max(w[h+11],index);
  }
  if(seen!==size)throw 0;w[G+7]=size-selectedKeys;if(w[G+7])w[G+4]|=32;
  for(let j=0;j<w[G+5];j++)if(w[j*64+9]<1||w[j*64+9]!==((w[j*64+8]&1?1:0)+(w[j*64+8]&2?1:0)))throw 0;
  // S: every same-numeric-ID row contributes its own identity components.
  for(let i=0;i<length;i++){
    const event=at(events,i),source=sameSource(event),slot=find(own(source,'id'));if(slot<0)continue;
    const h=slot*64;w[h+57]++;accumulate(w,h,source,false);const ec=eventCode(w,event),ph=phase(w,event);
    if(ec===18&&ph===1){w[h+12]++;if(w[h+12]===1)w[h+14]=i;}
    if(ec===18&&ph===2){w[h+13]++;if(w[h+13]===1)w[h+15]=i;}
    if(ec===17){const bytes=own(paramsOf(event),'byte_count');w[h+(!numericInteger(bytes,0,2147483647)?28:bytes>0?26:27)]++;}
  }
  for(let j=0;j<w[G+5];j++){
    const h=j*64;w[h+2]=identity(w[h+62]);w[h+1]=kind(w[h+3]);
    if(w[h+2]!==0){w[h+25]|=w[h+2]===3?2:1;w[G+4]|=64;clearController(w,h,5,1);continue;}
    const rel=anchor?delta(w,h+4,S+3,-300000):NIL;w[h+7]=rel;if(rel===NIL){w[h+25]|=1024;w[G+4]|=4096;}
    if(w[h+28]){w[h+25]|=16384;w[G+4]|=8192;}
    if(w[h+1]!==1){w[h+25]|=1;w[G+4]|=64;clearController(w,h,5,1);continue;}
    const outside=w[h+12]===1&&(w[h+10]<w[h+14]||w[h+13]===1&&w[h+11]>w[h+15]);
    if(w[h+12]>1||w[h+13]>1||w[h+12]===1&&w[h+13]===1&&w[h+15]<w[h+14]||outside){
      w[h+2]=3;w[h+7]=NIL;if(w[h+12]>1)w[h+25]|=4;if(w[h+13]>1)w[h+25]|=8;if(outside)w[h+25]|=16;
      w[G+4]|=16448;clearController(w,h,4,1);continue;}
    if(w[h+12]!==1){clearController(w,h,1,1);continue;}
    const dep=dependency(paramsOf(at(events,w[h+14])),signed(w[h]));
    if(dep===ABSENT){clearController(w,h,1,1);continue;}
    if(dep===BAD){w[h+25]|=32;clearController(w,h,3,1);continue;}
    w[h+17]=encoded(own(dep,'id'));w[h+63]=own(dep,'type');w[h+16]=0;
  }
  // C: ID FIRST. No type prefilter can hide missing/malformed/conflicting rows.
  for(let i=0;i<length;i++){
    const source=sameSource(at(events,i)),value=own(source,'id');
    for(let j=0;j<w[G+5];j++){const h=j*64;if(w[h+16]===0&&signed(w[h+17])===value){w[h+59]++;accumulate(w,h,source,true);}}
  }
  for(let j=0;j<w[G+5];j++){
    const h=j*64;if(w[h+16]!==0)continue;
    const ident=identity(w[h+61]);
    if(!w[h+59])clearController(w,h,6,1);
    else if(ident===3)clearController(w,h,8,3);
    else if(ident===2)clearController(w,h,7,2);
    else if(ident===1)clearController(w,h,9,1);
    else if(w[h+19]!==w[h+63])clearController(w,h,7,2);
    else {w[h+20]=0;w[h+18]=kind(w[h+19]);if(w[h+18]<2)clearController(w,h,2,0);
      else {w[h+24]=anchor?delta(w,h+21,S+3,-300000):NIL;if(w[h+24]===NIL){w[h+25]|=1024;w[G+4]|=4096;}}}
    if(w[h+16]!==0){w[G+4]|=128;w[h+25]|=w[h+20]===3?128:64;}
  }
  // E: last eight selected whitelist observations per target, no parent verdict.
  for(let i=0;i<length;i++){
    const event=at(events,i),source=sameSource(event),value=own(source,'id'),ec=eventCode(w,event);if(ec<1||ec>14)continue;
    for(let j=0;j<w[G+5];j++){
      const h=j*64;if(w[h+16]!==0||signed(w[h+17])!==value)continue;
      const ph=phase(w,event),duration=ec===1?32:ec===2?36:ec===3?40:ec===9?44:ec===11?48:ec===12?52:-1;
      if(duration>=0&&(ph===1||ph===2)){const k=h+duration+(ph===1?0:1);w[k]++;if(w[k]===1)w[h+duration+(ph===1?2:3)]=i;}
      const ring=1024+j*64+(w[h+31]%8)*8;w[h+31]=(w[h+31]+1)%8;w[h+29]++;w[h+30]=Math.min(8,w[h+30]+1);
      w[ring]=i;w[ring+1]=ec;w[ring+2]=ph;w[ring+3]=anchor&&tick(w,own(event,'time'))?delta(w,S,S+3,0):NIL;
      const params=paramsOf(event),net=own(params,'net_error'),os=own(params,'os_error'),cancel=own(params,'cancel_reason');
      w[ring+4]=net===ABSENT?0:!numericInteger(net,-2147483648,2147483647)?7:net===0?1:net===-3?2:net===-7?3:net===-331?4:net<0?5:6;
      w[ring+5]=os===ABSENT?0:!numericInteger(os,-2147483648,2147483647)?4:os===0?1:os>0?2:3;
      let cr=cancel===ABSENT?0:typeof cancel!=='string'?13:12;for(let k=0;k<11;k++)if(cancel===CANCEL[k])cr=k+1;w[ring+6]=cr;
      const dep=own(params,'source_dependency');let ref=2;
      if(plain(dep)){const dt=own(dep,'type'),di=own(dep,'id');if(code(dt)&&id(di))ref=dt===w[h+3]&&di===signed(w[h])?1:0;}
      else if(dep!==ABSENT){w[h+25]|=256;}
      if(ref===2&&dep!==ABSENT)w[h+25]|=256;w[ring+7]=ref;
      if(w[ring+3]===NIL){w[h+25]|=1024;w[G+4]|=4096;}if(w[ring+4]>=6)w[h+25]|=2048;if(w[ring+5]===4)w[h+25]|=4096;if(cr>=12)w[h+25]|=8192;
    }
  }
  for(let j=0;j<w[G+5];j++){
    const h=j*64;if(w[h+16]!==0)continue;let ambiguous=false;
    for(let k=32;k<=52;k+=4)if(w[h+k]>1||w[h+k+1]>1||w[h+k]===1&&w[h+k+1]===1&&w[h+k+3]<w[h+k+2])ambiguous=true;
    if(ambiguous){clearController(w,h,8,3);w[h+25]|=128;w[G+4]|=128;}
    else if(w[h+29]>8){w[h+25]|=512;w[G+4]|=256;}
  }
  if(Reflect.getOwnPropertyDescriptor(Map.prototype,'size').get.call(pending)!==size||arrayLength(events)!==length)throw 0;
}
// Bounded token emitter writes actual root-depth pretty JSON, before allocation.
function emit(w,b,shown,status,flags,cap){
  let pos=0;const put=text=>{for(let i=0;i<text.length;i++){if(pos>=cap-33)throw 0;b[pos++]=text.charCodeAt(i);}};
  const scalar=value=>{if(value===null)put('null');else if(typeof value==='boolean')put(value?'true':'false');else {if(!integer(value,-2147483648,2147483647))throw 0;put(''+value);}};
  const indent=depth=>{for(let i=0;i<depth*2;i++)put(' ');};
  const open=()=>put('['),close=()=>put(']');
  const item=(index,depth,fn)=>{if(index)put(',');put('\n');indent(depth);fn();};
  const end=(count,depth)=>{if(count){put('\n');indent(depth);}close();};
  let keys=0;for(let j=shown;j<w[G+5];j++)keys+=w[j*64+9];
  put('{');
  for(let root=0;root<10;root++){
    if(root)put(',');put('\n    "'+ROOT_KEYS[root]+'": ');
    if(root<9){scalar(root===0?1:root===1?status:root===2?nullable(w[G+6]):root===3?status===2?0:w[G+5]:root===4?shown:root===5?nullable(w[G+7]):root===6?status===2?0:w[G+5]-shown:root===7?status===2?0:keys:flags);continue;}
    open();for(let j=0;j<shown;j++)item(j,3,()=>{
      const h=j*64,valid=w[h+2]===0,socket=valid&&w[h+1]===1;open();
      for(let col=0;col<20;col++)item(col,4,()=>{
        const resolved=w[h+16]===0;
        if(col===16){if(!socket){scalar(null);return;}open();for(let k=0;k<3;k++)item(k,5,()=>scalar(w[h+26+k]));end(3,4);}
        else if(col===19){open();const count=resolved?w[h+30]:0;for(let e=0;e<count;e++)item(e,5,()=>{open();const ring=1024+j*64+((w[h+31]-count+e+8)%8)*8;for(let k=0;k<8;k++)item(k,6,()=>scalar(k===3?relative(w[ring+3]):k===7?w[ring+7]===2?null:w[ring+7]===1:w[ring+k]));end(8,5);});end(count,4);}
        else scalar(col===0?signed(w[h]):col===1?w[h+1]:col===2?w[h+2]:col===3?valid?relative(w[h+7]):null:col===4?w[h+8]:col===5?w[h+9]:col===6?w[h+10]:col===7?socket?w[h+12]:null:col===8?socket?w[h+13]:null:col===9?socket&&w[h+13]===1?nullable(w[h+15]):null:col===10?w[h+16]:col===11?resolved?signed(w[h+17]):null:col===12?resolved?w[h+18]:0:col===13?w[h+20]:col===14?resolved?relative(w[h+24]):null:col===15?w[h+25]:col===17?resolved?w[h+29]:null:resolved?w[h+29]-w[h+30]:null);
      });end(20,3);
    });end(shown,2);
  }
  put('\n  }');return pos;
}
function validate(value){
  if(!plain(value)||Object.keys(value).join('|')!==ROOT_KEYS.join('|'))return false;
  if(value.schema_version!==1||!integer(value.status,0,2)||!integer(value.flags,0,65535))return false;
  const pending=value.pending_keys,unselected=value.unselected_keys,selected=value.selected_sources,shown=value.shown_sources,trim=value.trimmed_sources,keys=value.trimmed_keys;
  if(!(pending===null&&value.status===2||integer(pending,0,100000))||!(unselected===null&&value.status===2||integer(unselected,0,100000)))return false;
  if(!integer(selected,0,16)||!integer(shown,0,16)||!integer(trim,0,16)||!integer(keys,0,32)||shown!==value.records.length||trim!==selected-shown||trim>keys||keys>2*trim)return false;
  if(value.status!==0&&shown!==0||value.status===2&&(selected||trim||keys)||value.status===0&&shown===0&&pending!==0)return false;
  let count=keys+(unselected??0),previous=-1;
  for(const r of value.records){
    if(!Array.isArray(r)||r.length!==20||!id(r[0])||!integer(r[1],0,10)||!integer(r[2],0,3)||!(r[3]===null||integer(r[3],-300000,300000))||!integer(r[4],1,3)||!integer(r[5],1,2)||!integer(r[6],0,99999)||r[6]<previous)return false;
    previous=r[6];count+=r[5];if(r[5]!==((r[4]&1?1:0)+(r[4]&2?1:0)))return false;
    for(const k of [7,8,17,18])if(!(r[k]===null||integer(r[k],0,100000)))return false;
    if(!(r[9]===null||integer(r[9],0,99999))||!integer(r[10],0,9)||!integer(r[13],0,3)||!integer(r[15],0,65535))return false;
    const pair=[0,1,0,1,1,1,1,2,3,1][r[10]];if(r[13]!==pair)return false;
    if(r[10]!==0){if(r[11]!==null||r[12]!==0||r[14]!==null||r[17]!==null||r[18]!==null||r[19].length)return false;}
    else if(!id(r[11])||!integer(r[12],2,10)||!(r[14]===null||integer(r[14],-300000,300000))||!integer(r[17],0,100000)||r[18]!==r[17]-r[19].length)return false;
    if(r[2]!==0){if(r[3]!==null||r[7]!==null||r[8]!==null||r[9]!==null||r[16]!==null||![4,5].includes(r[10]))return false;}
    else if(r[16]!==null&&(!Array.isArray(r[16])||r[16].length!==3||!r[16].every(x=>integer(x,0,100000))))return false;
    if(!Array.isArray(r[19])||r[19].length>8)return false;
    let prior=-1;for(const e of r[19]){if(!Array.isArray(e)||e.length!==8||!integer(e[0],0,99999)||e[0]<=prior||!integer(e[1],1,14)||!integer(e[2],0,3)||!(e[3]===null||integer(e[3],0,300000))||!integer(e[4],0,7)||!integer(e[5],0,4)||!integer(e[6],0,13)||!(e[7]===null||typeof e[7]==='boolean'))return false;prior=e[0];}
  }
  return pending===null||count===pending;
}
export function createTCPLifecycleDiagnostics(){
  try {
    const {words,bytes}=createStartupReceiptArena();
    let adopted=null,created=false;
    const cleanup=checks=>{if(created){const d=Object.getOwnPropertyDescriptor(checks,KEY);if(d&&Object.hasOwn(d,'value')&&d.value===adopted)delete checks[KEY];}created=false;adopted=null;};
    return {
      receipt:words,
      attach(checks,log,pending,names){
        try {
          if(!plain(checks)||Object.getOwnPropertyDescriptor(checks,KEY)||words[G+2]!==1||words[G+3]!==1||words[G+1]!==1||!integer(words[G],0,262144))return;
          // Known production nonempty plain root; receipt must precede this call.
          if(own(checks,'synthetic')!==true)return;
          const cap=Math.min(4096,262144-words[G]);if(cap<33)return;
          try {collect(words,checks,log,pending,names);}catch{words[G+4]|=9;words[G+5]=0;words[G+7]=words[G+6];words[G+8]=2;}
          let shown=words[G+8]===2?0:words[G+5],status=words[G+8],length=-1,flags=words[G+4];
          if(status===0&&shown===0&&words[G+6]!==0)status=1;
          for(;;){
            // One emission per prefix at the independent detail cap. A complete
            //length also decides checks room; overflow exceeds both when room
            //is smaller. Flags only grow, so a failed prefix cannot become fit.
            try {length=emit(words,bytes,shown,status,flags,4096);if(33+length<=cap)break;
              const next=flags|1024;flags=33+length+digits(next)-digits(flags)>4096?next|512:next;}
            catch{flags|=512;if(cap<4096)flags|=1024;}
            if(status===2||shown===0){if(status===0){status=1;continue;}return;}
            shown--;if(shown===0)status=1;
          }
          // One bounded ASCII materialization, only after final prefix selection.
          for(let i=length;i<4096;i++)bytes[i]=32;
          const ascii=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
          const value=JSON.parse(ascii);if(!validate(value)||33+length>cap)return;
          adopted=value;Object.defineProperty(checks,KEY,{value,writable:true,enumerable:true,configurable:true});
          const d=Object.getOwnPropertyDescriptor(checks,KEY);created=!!d&&Object.hasOwn(d,'value')&&d.value===value;
          if(!created)return;
          // Check only bounded trusted adopted value, never serialize baseline.
          if(!validate(value))cleanup(checks);
        }catch{try{cleanup(checks);}catch{ /* New field only. */ }}
      },
      cleanup
    };
  }catch{return null;}
}
