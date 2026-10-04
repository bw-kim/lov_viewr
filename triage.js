'use strict';
// Human-facing incident categories. The original records remain available in the detail view.
const focusNames={key:'핵심 기록',in:'들어온 SSH',out:'나간 SSH',file:'이름변경·삭제',mysql:'MySQL',all:'전체 원문'};
let activeFocus='key';
const otherIncident=Object.freeze({focus:'other',title:'기타 기록',summary:'',stage:'원문',peer:'',account:'',paths:[],caution:'분류되지 않은 원문입니다.'});
const auditValue=(raw,key)=>{const m=raw.match(new RegExp('\\b'+key+'=(?:"([^"]*)"|(\\S+))'));return m?(m[1]??m[2]).replace(/['"]+$/,''):''};
const cleanValue=v=>v&&v!=='?'&&v!=='(none)'&&v!=='unknown'?v:'';
const shortText=(v,max=180)=>String(v||'').replace(/\s+/g,' ').trim().slice(0,max);

function classifyIncident(e){
 const raw=e.raw,decoded=e.decoded||'',source=e.source||'',audit=/\btype=[A-Z_]+\s+msg=audit\(/.test(raw),type=(raw.match(/\btype=(USER_[A-Z_]+|SYSCALL|EXECVE)\b/)||[])[1]||'';
 const exe=auditValue(raw,'exe'),acct=cleanValue(auditValue(raw,'acct')),peer=cleanValue(auditValue(raw,'addr'))||cleanValue(auditValue(raw,'hostname'))||(raw.match(/\bfrom\s+([\da-f:.]+)\b/i)||[])[1]||'';
 const res=auditValue(raw,'res'),sysOk=auditValue(raw,'success'),account=acct||(raw.match(/\bfor (?:invalid user |user )?([\w.@-]+)/i)||[])[1]||'';
 const result=(focus,title,summary,stage,caution='',paths=[])=>({focus,title,summary,stage,peer,account,paths,caution});

 // sshd is the server side. USER_ACCT is a successful account check, not a successful login.
 if((/\bsshd(?:\[|\b)/i.test(raw)||/\/sshd\b/.test(exe)) && (type.startsWith('USER_')||/Accepted |Failed password|Invalid user|session (?:opened|closed)/i.test(raw))){
  if(type==='USER_ACCT')return result('in','들어온 SSH',`SSH 계정 검사 ${res==='success'?'통과':res==='failed'?'실패':'기록'}`,'계정 검사','이 기록 하나만으로 로그인 완료를 뜻하지 않습니다.');
  if(type==='USER_AUTH'||/Failed password|Invalid user/i.test(raw))return result('in','들어온 SSH',res==='success'||/Accepted /i.test(raw)?'SSH 인증 성공':'SSH 인증 실패','인증',res==='success'?'인증 성공 뒤 실제 세션 시작 기록을 확인하세요.':'');
  if(type==='USER_LOGIN')return result('in','들어온 SSH',res==='success'?'SSH 로그인 성공':'SSH 로그인 실패','로그인','실제 명령 실행 여부는 세션·프로세스 기록을 확인하세요.');
  if(type==='USER_START'||/session opened/i.test(raw))return result('in','들어온 SSH','SSH 세션 시작','세션 시작');
  if(type==='USER_END'||/session closed/i.test(raw))return result('in','들어온 SSH','SSH 세션 종료','세션 종료');
  if(/Accepted (?:password|publickey|keyboard-interactive)/i.test(raw))return result('in','들어온 SSH','SSH 인증 성공','인증','세션 시작 여부는 이어지는 기록을 확인하세요.');
  return result('in','들어온 SSH','sshd 계정·인증 기록','인증 단계');
 }

 // Outbound means an SSH client tool ran on this server. A process record alone does not prove a connection.
 const command=(raw.match(/\bCOMMAND=([^\n]+)/)||[])[1]||decoded;
 const auditExec=!audit||/\btype=EXECVE\b|\bsyscall=(?:59|322|execve|execveat)\b/i.test(raw);
 const clientExe=/\/(?:ssh|scp|sftp|rsync)(?:\s|$|\")/.test(exe+' ');
 const clientCommand=/(?:^|[\s/])(?:ssh|scp|sftp|rsync)(?=\s|$)/i.test(command)&&(/\bCOMMAND=|\ba0=|\bproctitle=|history/i.test(raw+' '+source)||!!decoded);
 if(auditExec&&(clientExe||clientCommand)){
  const tool=(exe.match(/\/(ssh|scp|sftp|rsync)$/)||command.match(/\b(ssh|scp|sftp|rsync)\b/i)||[])[1]||'SSH';
  const target=(command.match(/(?:[\w.-]+@)?((?:\d{1,3}\.){3}\d{1,3}|[\w.-]+):(?:\/|\w)/)||command.match(/\b(?:[\w.-]+@)?((?:\d{1,3}\.){3}\d{1,3})\b/)||[])[1]||'';
  const item=result('out','나간 SSH',`${tool.toUpperCase()} 도구 실행 흔적${target?' · 대상 '+target:''}`,'클라이언트 실행','실제 외부 접속·파일 전송 성공은 네트워크 기록이나 도구 결과로 확인하세요.');
  item.peer=target||peer;return item;
 }

 // A successful audit syscall gives stronger evidence than a shell command alone.
 const syscall=Number(auditValue(raw,'syscall')),arch=auditValue(raw,'arch').toLowerCase();
 const byNumber=arch==='c000003e'?{82:'rename',84:'rmdir',87:'unlink',263:'unlinkat',264:'renameat',316:'renameat2'}:{};
 const name=auditValue(raw,'syscall'),operation=/^(?:rename|renameat|renameat2|unlink|unlinkat|rmdir)$/.test(name)?name:byNumber[syscall];
 if(audit&&type==='SYSCALL'&&operation){
  const records=[...raw.matchAll(/\btype=PATH\b[^\n]*?\bname="([^"]+)"[^\n]*?(?:\bnametype=(\w+))?/g)].map(m=>({name:m[1],kind:m[2]||''}));
  const names=records.length?records:[...raw.matchAll(/\bname="([^"]+)"/g)].map(m=>({name:m[1],kind:''}));
  const old=names.find(p=>p.kind==='DELETE')?.name||names[0]?.name||'',newPath=names.find(p=>p.kind==='CREATE')?.name||(operation.startsWith('rename')?names.find(p=>p.name!==old)?.name:'')||'';
  const rename=operation.startsWith('rename'),target=rename?(old&&newPath?`${old} → ${newPath}`:old||newPath||'경로 미확인'):(old||'경로 미확인');
  const action=rename?'파일 이름변경':operation==='rmdir'?'디렉터리 삭제':'파일 삭제';
  const state=sysOk==='yes'?'성공':sysOk==='no'?'실패':'결과 미확인';
  return result('file','이름변경·삭제',`${action} ${state} · ${target}`,'audit 시스템 호출',sysOk==='yes'?'audit 기록상 시스템 호출 성공입니다. 경로는 PATH 기록을 확인하세요.':'PATH와 원문으로 작업 대상을 확인하세요.',names.map(p=>p.name));
 }
 const shellCommand=(raw.match(/\bCOMMAND=([^\n]+)/)||[])[1]||(/history/i.test(source)?raw:'');
 if(/(?:^|\s|\/)(?:mv|rm)(?:\s|$)/.test(shellCommand)){
  const action=/\bmv\b/.test(shellCommand)?'이름변경 명령':'삭제 명령';
  return result('file','이름변경·삭제',`${action} 실행 흔적 · ${shortText(shellCommand,150)}`,'명령 기록','명령 기록만으로 파일 작업 성공을 확정할 수 없습니다.');
 }

 const dump=/\b(?:mysqldump|mariadb-dump|mysqlpump|mydumper)\b/i.test(raw+' '+decoded);
 const mysqlSource=/mysql|mariadb|general\.log|slow\.log/i.test(source);
 const mysqlLine=/\b(?:Connect|Quit|Query|Init DB|Execute|Prepare)\b|Access denied|\bINTO\s+(?:OUTFILE|DUMPFILE)\b/i.test(raw);
 if(dump&&auditExec||mysqlSource&&mysqlLine){
  if(dump&&auditExec)return result('mysql','MySQL','DB 덤프 도구 실행 흔적 · '+shortText(command||raw,130),'덤프 도구','덤프 완료·반출 여부는 파일과 전송 기록을 확인하세요.');
  if(/Access denied/i.test(raw))return result('mysql','MySQL','DB 접속 거부','인증 실패');
  if(/\bConnect\b/i.test(raw))return result('mysql','MySQL','DB 연결 요청','접속','연결 기록과 실제 질의 실행은 구분해서 보세요.');
  if(/\bQuit\b/i.test(raw))return result('mysql','MySQL','DB 연결 종료','종료');
  const query=(raw.match(/\b(?:Query|Execute|Prepare)\s+([^\n]+)/i)||[])[1]||raw;
  const verb=(query.match(/\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|GRANT|REVOKE|SHOW|SET|USE|FLUSH)\b/i)||[])[1]||'질의';
  return result('mysql','MySQL',`DB ${verb.toUpperCase()} · ${shortText(query,150)}`,'질의 기록','일반 로그의 질의 기록은 서버가 받은 질의를 나타냅니다. 완료 여부는 별도 증거가 필요합니다.');
 }
 return otherIncident;
}

function renderFocusTabs(){const counts={key:0,in:0,out:0,file:0,mysql:0,all:0};for(const e of events){if(!sourceSelection.has(e.fileId))continue;counts.all++;const kind=e.triage.focus;if(kind!=='other'){counts.key++;counts[kind]++}}document.getElementById('focusTabs').innerHTML=Object.entries(focusNames).map(([key,label])=>`<button type="button" class="focus-tab ${activeFocus===key?'active':''}" data-focus="${key}" aria-pressed="${activeFocus===key}">${label}<small>${counts[key].toLocaleString()}</small></button>`).join('');document.getElementById('focusNote').textContent=activeFocus==='in'?'서버에 들어온 SSH입니다. 계정 검사, 인증, 로그인, 세션 시작을 각각 구분합니다.':activeFocus==='out'?'이 서버에서 SSH 클라이언트 도구가 실행된 흔적입니다. 접속 성공 여부는 별도로 확인하세요.':activeFocus==='file'?'audit 시스템 호출의 성공 여부와 PATH 경로를 함께 보여줍니다.':activeFocus==='mysql'?'접속·질의·덤프 도구 흔적을 보여줍니다. 덤프 완료 여부는 별도로 확인하세요.':activeFocus==='all'?'분류되지 않은 audit 기록까지 모두 표시합니다.':'SSH, 파일 이름변경·삭제, MySQL 관련 기록을 먼저 보여줍니다.'}

// Count all three sidebar fields in one pass for large cases.
updateCards=function(){let clues=0,unknown=0,stars=0;for(const e of events){if(e.tags.some(t=>t==='dump'||t==='transfer'||t==='archive'))clues++;if(e.ts==null)unknown++;if(noteOf(e).star)stars++}$('total').textContent=events.length.toLocaleString();$('clues').textContent=clues.toLocaleString();$('unknown').textContent=unknown.toLocaleString();$('starCount').textContent=stars.toLocaleString()};
renderEntities=function(){const fields=['ips','users','paths'],counts={ips:new Map(),users:new Map(),paths:new Map()};for(const e of events)for(const field of fields)for(const val of e[field]){if(field==='paths'&&!/\.(sql|dump|bak|gz|zip|tgz|7z)\b/i.test(val))continue;const map=counts[field];map.set(val,(map.get(val)||0)+1)}for(const field of fields)$(field).innerHTML=[...counts[field]].sort((a,b)=>b[1]-a[1]).slice(0,40).map(([val,n])=>'<button data-entity="'+esc(val)+'" data-field="'+field+'" title="이 값이 추출된 기록만 표시">'+esc(val)+' <span class="muted">'+n+'</span></button>').join('')||'<span class="muted">추출된 단서 없음</span>'};

const originalFinishLoad=finishLoad;
finishLoad=function(progressive=false){
 if(!progressive||events.length<50000){for(const e of events)if(!e.triage)e.triage=classifyIncident(e);originalFinishLoad();return Promise.resolve(true)}
 return new Promise(resolve=>{
  let index=0,lastNotice=0;
  const next=()=>{
   if(!busy){resolve(false);return}
   const deadline=performance.now()+12;
   while(index<events.length&&performance.now()<deadline){const e=events[index++];if(!e.triage)e.triage=classifyIncident(e)}
   if(index<events.length){if(performance.now()-lastNotice>700){status('기록 분류 중 · '+index.toLocaleString()+' / '+events.length.toLocaleString()+'건');lastNotice=performance.now()}setTimeout(next,0)}
   else{status('목록 구성 중 · '+events.length.toLocaleString()+'건');originalFinishLoad();resolve(true)}
  };
  setTimeout(next,0);
 });
};

applyFilters=function(){
 const words=terms().filter(Boolean),start=inputTime('start'),end=inputTime('end'),mode=$('searchMode').value;
 filtered=events.filter(e=>{
  const t=e.triage||(e.triage=classifyIncident(e));
  if(!sourceSelection.has(e.fileId))return false;
  if(activeFocus!=='all'&&(activeFocus==='key'?t.focus==='other':t.focus!==activeFocus))return false;
  if(activeEntity&&!e[activeEntity.field].includes(activeEntity.value))return false;
  if($('onlyStars').checked&&!noteOf(e).star)return false;
  if($('onlyUnknown').checked&&e.ts!=null)return false;
  if(start!=null&&(e.ts==null||e.ts<start))return false;
  if(end!=null&&(e.ts==null||e.ts>end))return false;
  if(!words.length)return true;
  const hay=(e.raw+' '+e.decoded+' '+e.source+' '+t.summary+' '+t.stage+' '+t.peer+' '+t.account+' '+t.paths.join(' ')).toLowerCase();
  return mode==='any'?words.some(w=>hay.includes(w)):words.every(w=>hay.includes(w));
 });
 const order=$('order').value;filtered.sort((a,b)=>order==='source'?a.fileId-b.fileId||a.line-b.line:a.ts==null&&b.ts==null?a.fileId-b.fileId||a.line-b.line:a.ts==null?1:b.ts==null?-1:(order==='desc'?b.ts-a.ts:a.ts-b.ts)||a.fileId-b.fileId||a.line-b.line);
 page=0;renderFocusTabs();if(chartDetails.open)renderHistogram();renderRows();
};

renderRows=function(){
 const size=+$('pageSize').value,pages=Math.ceil(filtered.length/size);page=Math.max(0,Math.min(page,Math.max(0,pages-1)));
 const list=filtered.slice(page*size,(page+1)*size);
 $('rows').innerHTML=list.map(e=>{const t=e.triage,loc=t.peer?`<span class="event-field">IP·대상 ${esc(t.peer)}</span>`:'',user=t.account?`<span class="event-field">계정 ${esc(t.account)}</span>`:'',path=t.paths.length?`<span class="event-field">경로 ${esc(t.paths.slice(0,2).join(' → '))}</span>`:'';
 return `<tr class="event" data-event="${e.id}" tabindex="0"><td colspan="5"><div class="event-card"><div class="event-time">${time(e.ts)}<span class="sub">${e.ts==null?'시각 미확인':e.assumed?'시간 가정 적용':'원문 시각'}</span></div><div class="event-main"><div class="event-top"><span class="event-type ${t.focus}">${esc(t.title)}</span><span class="event-stage">${esc(t.stage)}</span></div><div class="event-summary">${highlight(t.summary||shortText(e.raw,200))}</div><div class="event-fields">${loc}${user}${path}</div><div class="event-source">${esc(e.source)} · ${e.line}${e.endLine!==e.line?'–'+e.endLine:''}행${noteOf(e).text?' · 메모 '+esc(shortText(noteOf(e).text,70)):''}</div>${t.caution&&activeFocus!=='all'?`<div class="event-caution">${esc(t.caution)}</div>`:''}</div><button class="event-star" data-star="${e.id}" aria-label="중요 표시" aria-pressed="${noteOf(e).star}">${noteOf(e).star?'★':'☆'}</button></div></td></tr>`}).join('');
 $('empty').hidden=filtered.length>0;$('empty').classList.add('focus-empty');$('empty').textContent=events.length?'조건에 맞는 기록이 없습니다. 조회 초기화로 모든 파일과 기간을 다시 표시할 수 있습니다.':'기록을 불러오면 여기에 표시됩니다.';
 $('resultCount').textContent=filtered.length.toLocaleString()+'건 표시 · '+events.length.toLocaleString()+'건 중';$('timeLabel').textContent='표시 '+tzLabel(offset());$('pageInfo').textContent=(pages?page+1:0)+' / '+pages;$('prev').disabled=page===0;$('next').disabled=page+1>=pages;
};

const originalOpenDetail=openDetail;
openDetail=function(e){originalOpenDetail(e);const t=e.triage||classifyIncident(e);$('detailFocus').innerHTML=`<strong>${esc(t.title)} · ${esc(t.summary||shortText(e.raw,200))}</strong><span>${esc(t.stage)}${t.caution?' · '+esc(t.caution):''}</span>`};

resetFilters=function(){clearTimeout(queryTimer);for(const id of ['query','start','end'])$(id).value='';$('searchMode').value='all';$('order').value='asc';$('onlyStars').checked=false;$('onlyUnknown').checked=false;activeKind='';activeEntity=null;activeFocus='key';sourceSelection=new Set(sources.map(s=>s.id));renderSources();applyFilters();status(events.length?'조회 조건을 초기화했습니다. 불러온 기록과 메모는 그대로 있습니다.':'조회 조건을 초기화했습니다.')};
$('reset').onclick=resetFilters;

exportCsv=function(){const rows=[['표시 시각','epoch_ms','구분','단계','읽기 쉬운 요약','주의','원본 시각 근거','출처','시작행','끝행','IP·대상','계정','경로','중요','메모','원문','audit인수해석']];for(const e of filtered){const t=e.triage;rows.push([e.ts==null?'':time(e.ts,true)+' '+tzLabel(offset()),e.ts??'',t.title,t.stage,t.summary||shortText(e.raw,200),t.caution,e.why,e.source,e.line,e.endLine,t.peer,t.account,t.paths.join('|'),noteOf(e).star?'Y':'',noteOf(e).text,e.raw,e.decoded])}download('사고로그_현재결과.csv','\uFEFF'+rows.map(r=>r.map(csvCell).join(',')).join('\r\n'),'text/csv;charset=utf-8')};
$('exportCsv').onclick=exportCsv;

const focusPanel=document.createElement('section');focusPanel.className='focus-panel';focusPanel.innerHTML='<div class="focus-heading"><strong>어떤 기록을 볼까요?</strong><span class="muted">한 줄 요약을 누르면 원문과 앞뒤 기록을 봅니다.</span></div><nav id="focusTabs" class="focus-tabs" aria-label="기록 종류"></nav><p id="focusNote" class="focus-note"></p>';
document.querySelector('.filters').before(focusPanel);
focusPanel.onclick=e=>{const tab=e.target.closest('[data-focus]');if(tab){activeFocus=tab.dataset.focus;applyFilters()}};
$('reset').textContent='조회 초기화';$('reset').title='검색어, 기간, 정렬, 중요 표시, 파일 선택, 기록 종류를 처음 상태로 돌립니다. 불러온 로그와 메모는 유지합니다.';
$('clear').textContent='불러온 자료 전체 제거';
const detailFocus=document.createElement('div');detailFocus.id='detailFocus';detailFocus.className='detail-focus';$('detailMeta').before(detailFocus);
const chartDetails=document.createElement('details');chartDetails.className='timeline-details';chartDetails.innerHTML='<summary>시간 분포 펼치기</summary>';
const histogram=$('histogram'),chartLabels=document.querySelector('.chart-labels');histogram.before(chartDetails);chartDetails.append(histogram,chartLabels);
chartDetails.addEventListener('toggle',()=>{if(chartDetails.open)renderHistogram()});
document.querySelector('.legend').textContent='요약은 조사 보조용입니다. SSH 계정 검사 통과는 로그인 성공과 다르고, 클라이언트 도구 실행은 외부 접속 성공과 다릅니다. 상세에서 원문과 앞뒤 기록을 확인하세요.';
document.querySelector('#clues').nextElementSibling.textContent='덤프·전송·압축 문자열 단서';
$('help').onclick=()=>showInfo('사용 안내','<p><b>1. 파일이나 폴더를 불러오세요.</b> 화면의 종류 버튼으로 들어온 SSH, 나간 SSH, 파일 이름변경·삭제, MySQL 기록을 따로 볼 수 있습니다. 핵심 기록은 이 네 종류를 모아 보여주고 전체 원문은 그 밖의 audit 기록까지 보여줍니다.</p><p><b>2. 시간과 형식을 맞추세요.</b> 왼쪽에서 원본 시간대, 화면 시간대, 연도를 조절할 수 있습니다. 형식이 다른 로그는 상단 로그 형식 조절에서 날짜 규칙을 등록하세요.</p><p><b>3. 한 줄 요약을 누르세요.</b> 원문, 같은 파일의 앞뒤 기록, 경로와 IP 단서가 나옵니다. USER_ACCT res=success는 계정 검사 통과이지 로그인 성공 확정이 아닙니다. 서버에서 실행된 ssh·scp 도구도 실제 연결·전송 완료를 의미하지 않습니다.</p><p><b>4. 조회 초기화</b>는 검색어, 기간, 파일 선택, 종류, 정렬을 초기 상태로 돌립니다. 불러온 기록과 메모는 유지합니다. 불러온 자료 전체 제거는 기록과 저장하지 않은 메모를 지웁니다.</p><p><b>5. 저장</b> 중요한 기록에 별과 메모를 붙이고 현재 결과 CSV나 메모 파일로 내려받으세요. 브라우저를 닫으면 기록과 메모는 남지 않습니다.</p><p>GZ·ZIP·TAR·TAR.GZ와 일반 텍스트를 브라우저에서 읽습니다. journal·wtmp·binlog 같은 바이너리는 먼저 텍스트로 변환한 출력을 넣어주세요. 파일은 외부로 전송되지 않습니다.</p>');

$('demo').onclick=()=>{if(originals.length){status('예시는 실제 자료와 섞이지 않도록 불러온 자료 전체 제거 후 사용할 수 있습니다.');return}
 const a='1790996400',files=[
  new File(['Oct  3 12:00:01 demo sshd[431]: Accepted publickey for analyst from 192.0.2.25 port 50122 ssh2\nOct  3 12:00:02 demo sshd[431]: pam_unix(sshd:session): session opened for user analyst\nOct  3 12:00:08 demo sudo: analyst : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/mysqldump --all-databases --result-file=/tmp/backup.sql\nOct  3 12:03:20 demo sudo: analyst : COMMAND=/usr/bin/scp /tmp/backup.sql analyst@198.51.100.7:/upload/\nOct  3 12:05:01 demo sshd[431]: session closed for user analyst\n'],'예시_auth.log'),
  new File([`type=USER_ACCT msg=audit(${a}.100:70): pid=431 uid=0 auid=4294967295 msg='op=PAM:accounting acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.9 addr=203.0.113.9 terminal=ssh res=success'\ntype=USER_LOGIN msg=audit(${a}.200:71): pid=431 uid=0 auid=4294967295 msg='op=login id=0 exe="/usr/sbin/sshd" hostname=203.0.113.9 addr=203.0.113.9 terminal=ssh res=success'\ntype=SYSCALL msg=audit(${a}.300:72): arch=c000003e syscall=82 success=yes exe="/usr/bin/mv"\ntype=PATH msg=audit(${a}.300:72): item=0 name="/tmp/backup.sql" nametype=DELETE\ntype=PATH msg=audit(${a}.300:72): item=1 name="/tmp/archive.sql" nametype=CREATE\ntype=SYSCALL msg=audit(${a}.400:73): arch=c000003e syscall=87 success=yes exe="/usr/bin/rm"\ntype=PATH msg=audit(${a}.400:73): item=0 name="/tmp/archive.sql" nametype=DELETE\ntype=SYSCALL msg=audit(${a}.500:74): arch=c000003e syscall=59 success=yes exe="/usr/bin/ssh"\ntype=EXECVE msg=audit(${a}.500:74): argc=2 a0="ssh" a1="198.51.100.8"\n`],'예시_audit.log'),
  new File(['2026-10-03T12:01:00.000000+09:00 10 Connect root@localhost on testdb\n2026-10-03T12:01:03.000000+09:00 10 Query SELECT * FROM accounts\n2026-10-03T12:02:30.000000+09:00 10 Quit\n'],'예시_mysql-general.log')
 ];$('sourceTz').value='540';addFiles(files)};
renderFocusTabs();renderRows();
