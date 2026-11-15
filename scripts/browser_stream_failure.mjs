// No I/O, timers or stream construction. The driver supplies existing sinks.
export const STREAM_FAILURE_TEXT='browser owned stream failed';
export function createStreamFailureControl({getClient, exitState, writeReceipt}) {
  const cancellationSentinel=new Error(STREAM_FAILURE_TEXT);
  let failed=false, cancelRequested=false, receiptAttempted=false, phase='running';
  function fail(error, role, operation) {
    const observedPhase=phase;
    failed=true;
    if(exitState.exitCode===undefined||exitState.exitCode===0||exitState.exitCode==='0')exitState.exitCode=1;
    const ownsReceipt=!receiptAttempted;
    receiptAttempted=true;
    const client=getClient();
    if(!cancelRequested&&client) {
      cancelRequested=true;
      try {client.close(cancellationSentinel, 'transport_closed');}
      catch { /* Failure is committed; the next checkpoint still rejects. */ }
    }
    if(ownsReceipt) {
      try {
        let code='other';
        try {
          const descriptor=Object.getOwnPropertyDescriptor(error, 'code');
          if(descriptor&&Object.hasOwn(descriptor, 'value')) {
            const value=descriptor.value;
            if(value==='ECONNRESET'||value==='EPIPE'||value==='ERR_STREAM_DESTROYED')code=value;
          }
        }catch { /* Reflection is optional evidence, never control state. */ }
        writeReceipt(`FAIL browser stream role=${role} phase=${observedPhase} operation=${operation} code=${code}\n`);
      }catch { /* No recursive diagnostic fallback or raw error output. */ }
    }
  }
  const connectError=error=>fail(error, 'deny_proxy_connect', 'error_event');
  const stderrError=error=>fail(error, 'chrome_stderr', 'error_event');
  return {
    get failed(){return failed;},
    isCancellation:error=>error===cancellationSentinel,
    checkpoint(){if(failed)throw cancellationSentinel;},
    cleanup(){phase='cleanup';},
    finalizing(){phase='finalizing';},
    emitted(){phase='emitted';},
    registerConnect(socket) {
      if(socket.listenerCount('error', connectError)>0)return false;
      socket.on('error', connectError);
      return true;
    },
    registerStderr(stderr) {stderr.on('error', stderrError);},
    endConnect(socket, response) {
      try {socket.end(response);}
      catch(error) {
        fail(error, 'deny_proxy_connect', 'end_throw');
        // Only this direct end-throw path owns one fallback attempt. The error
        // handlers never destroy, including when destroy emits synchronously.
        try {socket.destroy();}catch { /* Failure remains; closure is unknown. */ }
      }
    }
  };
}
