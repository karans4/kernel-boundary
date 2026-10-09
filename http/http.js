import { BpfObject, RingBuf } from "yeet:bpf";
const control = await new BpfObject({exe:"./http.bpf.o",base:import.meta.dirname})
  .bind("events",{kind:"ringbuf",btf_struct:"http_event"})
  .attach("on_ingress",{kind:"tcx",ifindex:[1]}).start();
await new RingBuf(control,"events").subscribe(w => {
 const e=w.http_event || w;
 const line=Array.from(e.data || []).slice(0,Number(e.captured)).map(c=>String.fromCharCode(c)).join("");
 const req=line.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT) ([^ ]+) HTTP\//);
 const resp=line.match(/^HTTP\/[0-9.]+ ([0-9]{3})/);
 if (!req && !resp) return;
 console.log(JSON.stringify({source:"eBPF TCX loopback",method:req?req[1]:null,path:req?req[2].split("?")[0]:null,status:resp?Number(resp[1]):null,sport:Number(e.sport),dport:Number(e.dport),timestamp:String(e.ts)}));
},e=>console.error(String(e)));
