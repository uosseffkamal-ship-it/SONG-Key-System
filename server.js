const http=require("http");
const fs=require("fs");
const path=require("path");
const crypto=require("crypto");
const {URL}=require("url");

const PORT=Number(process.env.PORT||3000);
const ADMIN_TOKEN=process.env.SONG_ADMIN_TOKEN;
if(!ADMIN_TOKEN){console.error("Set SONG_ADMIN_TOKEN first.");process.exit(1);}

const ROOT=__dirname, DB_FILE=path.join(ROOT,"song_data.json");
function load(){try{return JSON.parse(fs.readFileSync(DB_FILE,"utf8"));}catch{return {visitors:{},requests:0,keysIssued:0,blocked:0,latencies:[],keys:{}};}}
let db=load();
db.visitors??={}; db.keys??={}; db.latencies??=[]; db.requests??=0; db.keysIssued??=0; db.blocked??=0;
const save=()=>fs.writeFileSync(DB_FILE,JSON.stringify(db,null,2));

function send(res,status,body,headers={}){
  const raw=typeof body==="string"?body:JSON.stringify(body);
  res.writeHead(status,{"Content-Type":typeof body==="string"?"text/plain; charset=utf-8":"application/json; charset=utf-8","Cache-Control":"no-store",...headers});
  res.end(raw);
}
function body(req){return new Promise((ok,bad)=>{let s="";req.on("data",c=>{s+=c;if(s.length>100000)req.destroy()});req.on("end",()=>{try{ok(s?JSON.parse(s):{})}catch(e){bad(e)}});req.on("error",bad)})}
function cookies(req){const o={};for(const p of (req.headers.cookie||"").split(";")){const i=p.indexOf("=");if(i>0)o[p.slice(0,i).trim()]=decodeURIComponent(p.slice(i+1).trim())}return o}
function vid(req){return cookies(req).song_vid||crypto.randomUUID()}
function admin(req){return (req.headers.authorization||"")==="Bearer "+ADMIN_TOKEN}
function key(){const b=crypto.randomBytes(18).toString("base64url").toUpperCase();return `SONG-${b.slice(0,6)}-${b.slice(6,12)}-${b.slice(12,18)}`}
function clean(){
  const cut=Date.now()-90*86400000;
  for(const [id,v] of Object.entries(db.visitors))if(v.lastSeen<cut)delete db.visitors[id];
  for(const [k,v] of Object.entries(db.keys))if(v.expiresAt<Date.now())delete db.keys[k];
  db.latencies=db.latencies.slice(-5000);
}
const MIME={".html":"text/html; charset=utf-8",".css":"text/css; charset=utf-8",".js":"text/javascript; charset=utf-8",".json":"application/json; charset=utf-8",".png":"image/png",".jpg":"image/jpeg",".svg":"image/svg+xml",".ico":"image/x-icon"};

http.createServer(async(req,res)=>{
  const started=Date.now(), u=new URL(req.url,`http://${req.headers.host||"localhost"}`);
  try{
    if(u.pathname==="/api/visit"&&req.method==="POST"){
      const id=vid(req),now=Date.now(),old=db.visitors[id];
      db.visitors[id]={firstSeen:old?.firstSeen||now,lastSeen:now,visits:(old?.visits||0)+1,keyTimes:old?.keyTimes||[]};
      clean();save();
      return send(res,200,{ok:true},{"Set-Cookie":`song_vid=${encodeURIComponent(id)}; Path=/; Max-Age=31536000; SameSite=Lax`});
    }

    if(u.pathname==="/api/key"&&req.method==="POST"){
      const x=await body(req);let target;
      try{target=new URL(String(x.url||""))}catch{db.blocked++;save();return send(res,400,{error:"INVALID_URL"})}
      if(!["http:","https:"].includes(target.protocol)||!target.hostname){db.blocked++;save();return send(res,400,{error:"INVALID_URL"})}

      const id=vid(req),now=Date.now(),v=db.visitors[id]||{firstSeen:now,lastSeen:now,visits:1,keyTimes:[]};
      v.keyTimes=(v.keyTimes||[]).filter(t=>t>now-600000);
      if(v.keyTimes.length>=10){db.blocked++;db.visitors[id]=v;save();return send(res,429,{error:"RATE_LIMIT"})}
      v.keyTimes.push(now);v.lastSeen=now;db.visitors[id]=v;

      const k=key(), requestId="SO-"+crypto.randomBytes(4).toString("hex").toUpperCase();
      const expiresAt=now+24*60*60*1000;
      db.keys[k]={createdAt:now,expiresAt,used:false,oneTime:true,requestId,target:target.hostname};
      db.requests++;db.keysIssued++;db.latencies.push(Date.now()-started);clean();save();
      return send(res,200,{ok:true,key:k,requestId,expiresAt});
    }

    if(u.pathname==="/api/validate-key"&&req.method==="POST"){
      const x=await body(req),k=String(x.key||"").trim(),v=db.keys[k];
      if(!v)return send(res,404,{valid:false,error:"KEY_NOT_FOUND"});
      if(v.expiresAt<Date.now())return send(res,410,{valid:false,error:"KEY_EXPIRED"});
      if(v.oneTime&&v.used)return send(res,409,{valid:false,error:"KEY_ALREADY_USED"});
      v.used=true;save();
      return send(res,200,{valid:true,expiresAt:v.expiresAt});
    }

    if(u.pathname==="/api/stats"&&req.method==="GET"){
      if(!admin(req))return send(res,401,{error:"UNAUTHORIZED"});
      const now=Date.now(),all=Object.values(db.visitors),d=new Date();d.setHours(0,0,0,0);
      const avg=db.latencies.length?Math.round(db.latencies.reduce((a,b)=>a+b,0)/db.latencies.length):0;
      return send(res,200,{
        totalVisitors:all.length,
        activeVisitors:all.filter(v=>v.lastSeen>now-300000).length,
        todayVisitors:all.filter(v=>v.firstSeen>=d.getTime()).length,
        requests:db.requests,keysIssued:db.keysIssued,blocked:db.blocked,avgLatency:avg,
        activeKeys:Object.values(db.keys).filter(k=>k.expiresAt>now&&!k.used).length
      });
    }

    const fp=path.join(ROOT,u.pathname==="/"?"song_key_system_FINAL.html":u.pathname);
    if(!fp.startsWith(ROOT))return send(res,403,"Forbidden");
    fs.stat(fp,(e,s)=>{
      if(e||!s.isFile())return send(res,404,"Not found");
      res.writeHead(200,{"Content-Type":MIME[path.extname(fp).toLowerCase()]||"application/octet-stream","Cache-Control":"no-cache"});
      fs.createReadStream(fp).pipe(res);
    });
  }catch(e){console.error(e);send(res,500,{error:"SERVER_ERROR"})}
}).listen(PORT,()=>console.log(`SONG KEY SYSTEM running on :${PORT}`));
