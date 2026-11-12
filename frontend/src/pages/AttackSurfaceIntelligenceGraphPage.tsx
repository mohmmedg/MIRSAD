import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { Download, Maximize2, Minimize2, Minus, Network, Plus, Search, Target } from "lucide-react";
import { useNavigate, useParams } from "react-router-dom";
import { exportAttackSurfaceGraph, type AttackGraphNode, type AttackSurfaceGraph } from "../api/client";
import { useLanguage } from "../i18n/LanguageContext";
import { useScan } from "../context/ScanContext";
import { PageHeader } from "../components/PageHeader";
import styles from "./AttackSurfaceIntelligenceGraphPage.module.css";
import { safeUserError } from "../utils/security";

type Point={x:number;y:number};
const TYPE_META:Record<string,{label:string;fill:string}>={domain:{label:"Domain",fill:"#5f8fa8"},subdomain:{label:"Subdomain",fill:"#70a080"},ip:{label:"IP",fill:"#7898a8"},dns:{label:"DNS",fill:"#8a8f9a"},certificate:{label:"SSL/TLS",fill:"#b29b55"},port:{label:"Port",fill:"#b37c45"},service:{label:"Service",fill:"#9a6c72"},technology:{label:"Technology",fill:"#668da0"},dns_record:{label:"DNS record",fill:"#777f91"},asset:{label:"Asset",fill:"#5f8f86"},endpoint:{label:"Endpoint",fill:"#8a979b"},api_endpoint:{label:"API",fill:"#8a7699"},finding:{label:"Finding",fill:"#b85a55"}};

// Logical drawing surface. Bigger than the old 1100x720 so nodes get real
// breathing room instead of bunching up — the SVG viewBox scales this to
// whatever pixel size the canvas container actually has (normal or
// fullscreen), so the graph always fills the space it's given.
const GRAPH_W=3000, GRAPH_H=1900;

function shorten(s:string,n=30){return s.length>n?`${s.slice(0,n-2)}…`:s}
function makeLayout(nodes:AttackGraphNode[], width:number, height:number):Record<string,Point>{
  const groups:Record<string,AttackGraphNode[]>={};
  nodes.forEach(n => (groups[n.type] ??= []).push(n));
  const out:Record<string,Point>={};
  const root=nodes.find(n=>n.type==="domain") ?? nodes.find(n=>n.type==="asset");
  const centerX=width/2;
  const marginX=180;
  const top=130;
  const tierGap=205;
  if(root) out[root.id]={x:centerX,y:90};

  // Keep semantic types in separate horizontal tiers. Each tier is centered
  // independently and uses a generous minimum gap so labels do not collide.
  const tiers=["subdomain","ip","dns","certificate","technology","port","service","asset","endpoint","api_endpoint","finding","dns_record"];
  const ordered=[...tiers.filter(t=>groups[t]?.length), ...Object.keys(groups).filter(t=>t!==root?.type&&!tiers.includes(t))];

  ordered.forEach((type,row)=>{
    const list=(groups[type]??[]).filter(n=>n.id!==root?.id);
    if(!list.length) return;

    // Up to six columns keeps large graphs readable. Additional nodes wrap
    // to a second row inside the same semantic tier rather than becoming
    // a dense single line.
    const columns=Math.min(6, Math.max(1, Math.ceil(Math.sqrt(list.length*1.35))));
    const usable=width-2*marginX;
    const gapX=Math.max(300, Math.min(470, usable/(columns-1||1)));
    const laneWidth=(columns-1)*gapX;
    const baseX=centerX-laneWidth/2;
    const rowGap=155;
    const tierY=top+row*tierGap;

    list.forEach((n,i)=>{
      const col=i%columns;
      const subrow=Math.floor(i/columns);
      const x=baseX+col*gapX;
      const y=tierY+subrow*rowGap;
      out[n.id]={
        x:Math.max(marginX,Math.min(width-marginX,x)),
        y:Math.min(height-120,y)
      };
    });
  });

  // Deterministic fallback for uncommon node types.
  nodes.forEach((n,i)=>{
    if(!out[n.id]){
      const col=i%6;
      const row=Math.floor(i/6);
      out[n.id]={
        x:marginX+col*Math.max(300,(width-2*marginX)/5),
        y:height-180-row*145
      };
    }
  });
  return out;
}
function detailsFor(node:AttackGraphNode|null){return node?JSON.stringify(node.details??{},null,2):""}

export function AttackSurfaceIntelligenceGraphPage(){
 const {scanId:routeScanId=""}=useParams(); const navigate=useNavigate(); const {language}=useLanguage(); const {unified, getCachedGraph, loadGraph}=useScan();
 const scanId = routeScanId || unified?.scan_id || "";
 const [graph,setGraph]=useState<AttackSurfaceGraph|null>(()=>scanId ? getCachedGraph(scanId) : null); const [selected,setSelected]=useState<AttackGraphNode|null>(null); const [query,setQuery]=useState(""); const [type,setType]=useState("all"); const [zoom,setZoom]=useState(1); const [pan,setPan]=useState({x:0,y:0}); const [drag,setDrag]=useState<{id:string;dx:number;dy:number}|null>(null); const [panDrag,setPanDrag]=useState<{x:number;y:number;px:number;py:number}|null>(null); const [positions,setPositions]=useState<Record<string,Point>>({}); const [error,setError]=useState<string|null>(null); const [fullscreen,setFullscreen]=useState(false); const svgRef=useRef<SVGSVGElement>(null);
 const ar=language==="ar";

 const labels=ar?{kicker:"ذكاء سطح الهجوم",title:"الرسم البياني لذكاء سطح الهجوم",sub:"رسم بياني مبني بالكامل من نتائج الفحص الفعلية",search:"ابحث في العقد...",all:"كل الأنواع",details:"تفاصيل العقدة",none:"اختر عقدة لعرض الأدلة والسجلات",export:"تصدير",back:"العودة إلى سطح الهجوم",zoom:"تكبير",out:"تصغير",reset:"إعادة ضبط",nodes:"العقد",edges:"الروابط",findings:"الثغرات",large:"وضع شبكة كبيرة — تم تقليل التسميات بصرياً",expand:"وضع ملء الشاشة",collapse:"إغلاق وضع ملء الشاشة"}:{kicker:"ATTACK SURFACE INTELLIGENCE",title:"Attack Surface Intelligence Graph",sub:"A factual graph generated from the persisted scan snapshot",search:"Search nodes...",all:"All types",details:"Node intelligence",none:"Select a node to inspect evidence and records",export:"Export",back:"Back to attack surface",zoom:"Zoom in",out:"Zoom out",reset:"Reset",nodes:"Nodes",edges:"Edges",findings:"Findings",large:"Large-network mode — labels are reduced for smooth rendering",expand:"Fullscreen",collapse:"Exit fullscreen"};
 useEffect(()=>{let cancelled=false;(async()=>{try{
   if(!scanId){ if(!cancelled)setGraph(null); return; }
   const cached=getCachedGraph(scanId);
   if(cached){
     setGraph(cached);
     setPositions(makeLayout(cached.nodes,GRAPH_W,GRAPH_H));
     return;
   }
   const g=await loadGraph(scanId);
   if(!cancelled){setGraph(g);setPositions(makeLayout(g.nodes,GRAPH_W,GRAPH_H));}
 }catch(e){if(!cancelled)setError(safeUserError(e,ar?"تعذر تحميل رسم ذكاء سطح الهجوم":"Unable to load intelligence graph"))}})();return()=>{cancelled=true}},[scanId,ar,getCachedGraph,loadGraph]);
 // Fullscreen = the canvas becomes a dedicated "page inside the page":
 // covers the whole viewport (over the sidebar/topbar) so there's far more
 // room to pan/zoom/drag nodes around. Esc always exits it, and it's torn
 // down automatically if the underlying scan/graph changes.
 useEffect(()=>{
   if(!fullscreen)return;
   function onKey(e:KeyboardEvent){ if(e.key==="Escape") setFullscreen(false); }
   window.addEventListener("keydown",onKey);
   const prevOverflow=document.body.style.overflow;
   document.body.style.overflow="hidden";
   return ()=>{ window.removeEventListener("keydown",onKey); document.body.style.overflow=prevOverflow; };
 },[fullscreen]);
 useEffect(()=>{ if(!scanId) setFullscreen(false); },[scanId]);
 const types=useMemo(()=>Array.from(new Set((graph?.nodes??[]).map(n=>n.type))),[graph]);
 const visibleNodes=useMemo(()=>{const q=query.trim().toLowerCase();return (graph?.nodes??[]).slice(0,2000).filter(n=>(type==="all"||n.type===type)&&(!q||`${n.label} ${n.value} ${n.type}`.toLowerCase().includes(q)))},[graph,query,type]);
 const visibleIds=useMemo(()=>new Set(visibleNodes.map(n=>n.id)),[visibleNodes]);
 const visibleEdges=useMemo(()=>graph?.edges.filter(e=>visibleIds.has(e.source)&&visibleIds.has(e.target))??[],[graph,visibleIds]);
 function pointerDown(e:ReactPointerEvent,node:AttackGraphNode){const p=positions[node.id]??{x:0,y:0};setDrag({id:node.id,dx:p.x-e.nativeEvent.offsetX,dy:p.y-e.nativeEvent.offsetY});setSelected(node);(e.currentTarget as Element).setPointerCapture?.(e.pointerId)}
 function pointerMove(e:ReactPointerEvent){if(panDrag){setPan(v=>({x:v.x+e.clientX-panDrag.px,y:v.y+e.clientY-panDrag.py}));setPanDrag({x:panDrag.x,y:panDrag.y,px:e.clientX,py:e.clientY});return}if(!drag)return;const svg=svgRef.current; if(!svg)return;const r=svg.getBoundingClientRect();const x=(e.clientX-r.left-pan.x-40)/zoom;const y=(e.clientY-r.top-pan.y-40)/zoom;setPositions(v=>({...v,[drag.id]:{x:x+drag.dx,y:y+drag.dy}}))}
 function downloadSvg(){const svg=svgRef.current;if(!svg)return;const clone=svg.cloneNode(true) as SVGSVGElement;clone.setAttribute("xmlns","http://www.w3.org/2000/svg");const blob=new Blob([new XMLSerializer().serializeToString(clone)],{type:"image/svg+xml"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=`mirsad-${scanId}-attack-surface.svg`;a.click();URL.revokeObjectURL(a.href)}
 async function exportData(fmt:"json"|"csv"|"dot"){const r=await exportAttackSurfaceGraph(scanId,fmt);if(!r.ok){setError(r.status ? `تعذر تصدير الرسم (${r.status}).` : "تعذر تصدير الرسم.");return}const blob=await r.blob();const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=`mirsad-${scanId}-graph.${fmt}`;a.click();URL.revokeObjectURL(a.href)}
 if(error)return <section className={styles.wrap}><div className={styles.panel}><div className={styles.error}>{error}</div></div></section>;
 if(!scanId)return <section className={`${styles.wrap} animateIn`}><div className={styles.emptyGraph}><div className={styles.emptyIcon}><Network size={28}/></div><h2>{ar?"لا يوجد فحص حالي":"No current scan"}</h2><p>{ar?"شغّل فحصًا أو اختر فحصًا محفوظًا من سجل الفحوصات لعرض خريطة سطح الهجوم.":"Run a scan or choose a saved scan from Scan History to view its attack-surface map."}</p><button className={styles.button} onClick={()=>navigate("/scan-history")}>{ar?"فتح سجل الفحوصات":"Open scan history"}</button></div></section>;
 if(!graph)return <section className={styles.wrap}><div className={styles.panel}>Loading intelligence graph…</div></section>;
 const large=visibleNodes.length>280;
 return <section className={`${styles.wrap} ${fullscreen?styles.fullscreen:""} animateIn`}>
  <PageHeader icon={Network} eyebrow={labels.kicker} title={labels.title} description={<><span className="ltr">{graph.target}</span> · {labels.sub}</>} actions={<div className={styles.toolbar}><button className={styles.button} onClick={()=>navigate("/attack-surface")}>{labels.back}</button><button className={styles.button} onClick={downloadSvg}><Download size={14}/>SVG</button><button className={styles.button} onClick={()=>exportData("json")}>JSON</button><button className={styles.button} onClick={()=>exportData("csv")}>CSV</button><button className={styles.button} onClick={()=>exportData("dot")}>DOT</button><button className={`${styles.button} ${styles.expandButton}`} title={fullscreen?labels.collapse:labels.expand} onClick={()=>setFullscreen(v=>!v)}>{fullscreen?<Minimize2 size={14}/>:<Maximize2 size={14}/>}{fullscreen?labels.collapse:labels.expand}</button></div>} />
  <div className={styles.toolbar}><div style={{position:"relative"}}><Search size={14} style={{position:"absolute",left:10,top:11,color:"var(--text-faint)"}}/><input className={styles.search} style={{paddingLeft:30}} value={query} onChange={e=>setQuery(e.target.value)} placeholder={labels.search}/></div><select className={styles.select} value={type} onChange={e=>setType(e.target.value)}><option value="all">{labels.all}</option>{types.map(t=><option key={t} value={t}>{TYPE_META[t]?.label??t}</option>)}</select></div>
  <div className={styles.layout}><div className={styles.canvas}><svg ref={svgRef} className={styles.svg} viewBox={`0 0 ${GRAPH_W} ${GRAPH_H}`} onPointerDown={e=>{if(e.target===e.currentTarget)setPanDrag({x:pan.x,y:pan.y,px:e.clientX,py:e.clientY})}} onPointerMove={pointerMove} onPointerUp={()=>{setDrag(null);setPanDrag(null)}} onWheel={e=>{e.preventDefault();setZoom(z=>Math.max(.35,Math.min(2.5,z*(e.deltaY<0?1.08:.92))))}}>
    <g transform={`translate(${pan.x+40},${pan.y+40}) scale(${zoom})`}>
      {visibleEdges.map(e=>{const a=positions[e.source],b=positions[e.target];if(!a||!b)return null;return <g key={e.id}><line className={styles.edge} x1={a.x} y1={a.y} x2={b.x} y2={b.y}/></g>})}
      {visibleNodes.map(n=>{const p=positions[n.id];if(!p)return null;const isSelected=n.id===selected?.id;return <g key={n.id} className={`${styles.node} ${isSelected?styles.selected:""}`} transform={`translate(${p.x},${p.y})`} onPointerDown={e=>{e.stopPropagation();pointerDown(e,n)}}><circle className={styles.nodeCircle} r={n.type==="domain"?20:n.type==="finding"?13:11} fill={TYPE_META[n.type]?.fill??"#8a979b"}/><><text className={styles.nodeText} textAnchor="middle" y={34}>{shorten(n.label,large?18:30)}</text><text className={styles.nodeSub} textAnchor="middle" y={49}>{n.type.toUpperCase()}</text></></g>})}
    </g></svg>
    <div className={styles.controls}><button className={styles.zoom} title={labels.zoom} onClick={()=>setZoom(z=>Math.min(2.5,z*1.2))}><Plus size={15}/></button><button className={styles.zoom} title={labels.out} onClick={()=>setZoom(z=>Math.max(.35,z*.83))}><Minus size={15}/></button><button className={styles.zoom} title={labels.reset} onClick={()=>{setZoom(1);setPan({x:0,y:0});setPositions(makeLayout(graph.nodes,GRAPH_W,GRAPH_H))}}><Target size={15}/></button></div>
  </div>
  <aside className={styles.panel}><div className={styles.statGrid}><div className={styles.stat}><span>{labels.nodes}</span><b>{graph.counts.nodes}</b></div><div className={styles.stat}><span>{labels.edges}</span><b>{graph.counts.edges}</b></div><div className={styles.stat}><span>{labels.findings}</span><b>{graph.counts.findings}</b></div><div className={styles.stat}><span>Visible</span><b>{visibleNodes.length}</b></div></div><div className={styles.panelTitle}>{labels.details}</div><div className={styles.legend}>{types.map(t=><div className={styles.legendItem} key={t}><i className={styles.dot} style={{background:TYPE_META[t]?.fill??"#8a979b"}}/><span>{TYPE_META[t]?.label??t}</span></div>)}</div>{large&&<p className={styles.hint}>{labels.large}</p>}{selected?<div className={styles.details}><b className="ltr">{selected.label}</b><div className="ltr" style={{margin:"4px 0 10px",color:"var(--text-faint)"}}>{selected.type} · degree {selected.degree}</div><pre>{detailsFor(selected)}</pre></div>:<p className={styles.hint}>{labels.none}</p>}</aside></div>
 </section>
}
