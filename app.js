
const $=s=>document.querySelector(s),arr=x=>x==null?[]:[].concat(x),SEV=['LOW','MEDIUM','HIGH','CRITICAL'],COL=['var(--l)','var(--m)','var(--h)','var(--c)'];
const D=x=>typeof x=='string'?JSON.parse(decodeURIComponent(x)):x;
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const rx=p=>new RegExp('^'+p.replace(/[.+^${}()|[\]\\]/g,'\\$&').replace(/\*/g,'.*').replace(/\?/g,'.')+'$','i');
const grants=(A,a)=>A.some(p=>rx(p).test(a));
const ESC=['iam:PassRole','iam:CreatePolicyVersion','iam:SetDefaultPolicyVersion','iam:AttachUserPolicy','iam:AttachRolePolicy','iam:AttachGroupPolicy','iam:PutUserPolicy','iam:PutRolePolicy','iam:PutGroupPolicy','iam:CreateAccessKey','iam:CreateLoginProfile','iam:UpdateAssumeRolePolicy','iam:AddUserToGroup'];
const COMPUTE=['ec2:RunInstances','lambda:CreateFunction','lambda:UpdateFunctionCode','cloudformation:CreateStack','glue:CreateDevEndpoint','ecs:RunTask'];
const SAFE={s3:['s3:GetObject','s3:PutObject','s3:ListBucket'],ec2:['ec2:DescribeInstances','ec2:StartInstances','ec2:StopInstances'],dynamodb:['dynamodb:GetItem','dynamodb:PutItem','dynamodb:Query'],lambda:['lambda:InvokeFunction','lambda:GetFunction'],sqs:['sqs:SendMessage','sqs:ReceiveMessage'],sns:['sns:Publish'],iam:['iam:GetRole','iam:ListRoles'],kms:['kms:Encrypt','kms:Decrypt']};
function fix(st){const o={Effect:'Allow',Action:[],Resource:arr(st.Resource).map(r=>r=='*'?'arn:aws:<service>:<region>:<account>:<specific-resource>':r)};
 arr(st.Action||st.NotAction).forEach(a=>{if(a=='*'||/:\*$/.test(a))o.Action.push(...(SAFE[a.split(':')[0]]||['<only-actions-this-identity-uses>']));else o.Action.push(a)});
 o.Action=[...new Set(o.Action)];if(st.Condition)o.Condition=st.Condition;
 return{note:'Replace the wildcard with only the actions and resource ARNs this identity needs. Example corrected statement (adjust the placeholders):',doc:{Version:'2012-10-17',Statement:[o]}}}
function analyze(d){
 const F=[],pm={},all=[...arr(d.UserDetailList).map(x=>({...x,t:'user',n:x.UserName})),...arr(d.GroupDetailList).map(x=>({...x,t:'group',n:x.GroupName})),...arr(d.RoleDetailList).map(x=>({...x,t:'role',n:x.RoleName}))];
 arr(d.Policies).forEach(p=>{const v=arr(p.PolicyVersionList).find(v=>v.IsDefaultVersion);if(v)pm[p.Arn]=v.Document});
 const own=k=>[...arr(k.UserPolicyList),...arr(k.GroupPolicyList),...arr(k.RolePolicyList)].map(p=>({name:p.PolicyName+' (inline)',doc:p.PolicyDocument})).concat(arr(k.AttachedManagedPolicies).map(p=>({name:p.PolicyName,doc:pm[p.PolicyArn]})));
 const grp={};all.filter(x=>x.t=='group').forEach(g=>grp[g.n]=own(g));
 const acct=((all.find(x=>x.Arn)||{Arn:''}).Arn.match(/::(\d{12}):/)||[])[1];
 all.forEach(k=>{
  const add=(sev,pol,title,why,ev,fx)=>F.push({sev,id:k.t+':'+k.n,pol,title,why,ev,fx});
  k.tr=[];k.pols=own(k).concat(k.t=='user'?arr(k.GroupList).flatMap(g=>(grp[g]||[]).map(p=>({...p,name:p.name+' via group '+g,inh:1}))):[]).filter(p=>p.doc);
  const eff=[];
  k.pols.forEach(p=>arr(D(p.doc).Statement).forEach(st=>{
   if(st.Effect!='Allow')return;const A=arr(st.Action),R=arr(st.Resource),W=R.includes('*');eff.push(...A);
   if(p.inh)return;const nm=p.name,x=fix(st);
   if(st.NotAction)add('HIGH',nm,'Allow with NotAction','Grants every action except those listed, almost always broader than intended.',st,x);
   if(A.includes('*'))add(W?'CRITICAL':'HIGH',nm,W?'Full admin: Action * on Resource *':'Action * on scoped resources','Every API action is allowed, so a compromise of this identity is a compromise of the account.',st,x);
   else{A.filter(a=>/:\*$/.test(a)).forEach(a=>add(a=='iam:*'?'CRITICAL':W?'HIGH':'MEDIUM',nm,`Service wildcard ${a}${W?' on all resources':''}`,'Grants every '+a.split(':')[0]+' action, including destructive and permission-changing ones.',st,x));
    if(W&&A.some(a=>!/:\*$/.test(a)&&!/:(Get|List|Describe)/i.test(a)))add('MEDIUM',nm,'Mutating actions on Resource "*"','Write actions are not limited to specific resources.',st,x)}
  }));
  if(!eff.includes('*')){const hit=ESC.filter(e=>grants(eff,e)),pc=hit.includes('iam:PassRole')?COMPUTE.filter(c=>grants(eff,c)):[];
   if(hit.length)add(pc.length?'CRITICAL':'HIGH','(combined permissions)',pc.length?'PassRole + compute service = privilege escalation':'IAM privilege-escalation permissions','These permissions let the identity grant itself more access (e.g. launch a compute resource with a powerful role).',{actions:hit.concat(pc)},{note:'Remove the escalation actions. If PassRole is needed, limit it to specific roles and services:',doc:{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'iam:PassRole',Resource:'arn:aws:iam::'+acct+':role/<specific-role>',Condition:{StringEquals:{'iam:PassedToService':'lambda.amazonaws.com'}}}]}})}
  if(k.t=='role')arr(D(k.AssumeRolePolicyDocument).Statement).forEach(st=>{if(st.Effect!='Allow')return;
   (st.Principal=='*'?['*']:arr((st.Principal||{}).AWS)).forEach(p=>{
    const a=(String(p).match(/\d{12}/)||[])[0],c=st.Condition,ex={note:'Trust a specific role, require an ExternalId and/or MFA, and avoid account-root or wildcard principals:',doc:{Version:'2012-10-17',Statement:[{Effect:'Allow',Principal:{AWS:'arn:aws:iam::<trusted-account>:role/<specific-role>'},Action:'sts:AssumeRole',Condition:{StringEquals:{'sts:ExternalId':'<shared-secret>'}}}]}};
    const T=(sev,title,why)=>{k.tr.push({a:a||'ANY (*)',sev:SEV.indexOf(sev)});add(sev,'Trust policy',title,why,st,ex)};
    if(p=='*')T(c?'HIGH':'CRITICAL','Role assumable by any AWS principal'+(c?' (condition-limited)':''),'Principal "*" lets any AWS account assume this role unless the Condition blocks it.');
    else if(a&&a!=acct)T(c?'MEDIUM':'HIGH','Cross-account trust to '+a+(c?'':' without Condition'),'An external account can assume this role'+(c?'.':' with no ExternalId, MFA or organization restriction (confused-deputy risk).'))})});
  const lu=k.t=='role'?(k.RoleLastUsed||{}).LastUsedDate:k.PasswordLastUsed,dd=lu&&Math.floor((Date.now()-new Date(lu))/864e5);
  if(k.t=='role'&&k.RoleLastUsed&&!lu)add('MEDIUM','n/a','Role never used','No recorded use. Unused roles widen the attack surface.',k.RoleLastUsed,{note:'Delete the role, or remove its policies, if no owner claims it.'});
  else if(dd>90)add('MEDIUM','n/a',`${k.t} unused for ${dd} days`,'Stale identities keep their permissions and are rarely monitored.',{lastUsed:lu},{note:'Disable credentials, confirm with the owner, then delete.'});
 });
 return{F,ids:all,acct}}
function render(r){
 const c={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};r.F.forEach(f=>c[f.sev]++);
 $('#sum').innerHTML=`<div class="card"><b style="font-size:22px">${r.ids.filter(k=>k.t!='group').length}</b><br><span class="mu">users and roles</span></div>`+SEV.slice().reverse().map(s=>`<div class="card"><span class="sev ${s}">${s}</span><br><b style="font-size:22px">${c[s]}</b></div>`).join('');
 $('#find').innerHTML=r.F.sort((a,b)=>SEV.indexOf(b.sev)-SEV.indexOf(a.sev)).map(f=>`<div class="card"><span class="sev ${f.sev}">${f.sev}</span> <b>${esc(f.title)}</b><div class="mu">${esc(f.id)} | policy: ${esc(f.pol)}</div><p>${esc(f.why)}</p><pre>${esc(JSON.stringify(f.ev,null,1))}</pre><details><summary>Least-privilege recommendation</summary><p>${esc(f.fx.note)}</p>${f.fx.doc?`<pre>${esc(JSON.stringify(f.fx.doc,null,1))}</pre>`:''}</details></div>`).join('')||'<div class="card">No findings.</div>';
 window.R=r;sel=null;drawGraph(r)}
let sel=null;
function drawGraph(r){
 const cols=[[],[],[],[]],idx={},E=[];
 const N=(c,key,label,sev=-1)=>{const n=idx[key]||(idx[key]={c,key,label,sev:-1,y:cols[c].length},cols[c].push(idx[key]),idx[key]);n.sev=Math.max(n.sev,sev);return n};
 const worst=k=>Math.max(-1,...r.F.filter(f=>f.id==k.t+':'+k.n).map(f=>SEV.indexOf(f.sev)));
 r.ids.filter(k=>k.t!='group').forEach(k=>{
  const i=N(1,'i'+k.t+k.n,(k.t=='user'?'user: ':'role: ')+k.n,worst(k));
  k.tr.forEach(t=>E.push([N(0,'x'+t.a,'acct '+t.a,t.sev).key,i.key,t.sev]));
  k.pols.forEach(p=>{const pn=N(2,'p'+p.name,p.name);
   arr(D(p.doc).Statement).forEach(st=>{if(st.Effect!='Allow')return;arr(st.Action).forEach(a=>{const v=a=='*'?3:/:\*$/.test(a)?2:-1,s=N(3,'s'+(a=='*'?'ALL':a.split(':')[0]),a=='*'?'ALL (*)':a.split(':')[0],v);pn.sev=Math.max(pn.sev,v);E.push([pn.key,s.key,v])})});
   E.push([i.key,pn.key,pn.sev])})});
 const act=new Set();if(sel)[0,1].forEach(d=>{const q=[sel];act.add(sel);while(q.length){const x=q.pop();E.forEach(e=>{const[a,b]=d?[e[0],e[1]]:[e[1],e[0]];if(a==x&&!act.has(b)){act.add(b);q.push(b)}})}});
 const X=[10,255,500,745],H=Math.max(...cols.map(c=>c.length))*30+20,pos=n=>[X[n.c],n.y*30+10];
 let s=`<svg viewBox="0 0 960 ${H}" width="100%" style="min-width:900px">`;
 E.forEach(([a,b,v])=>{const[x1,y1]=pos(idx[a]),[x2,y2]=pos(idx[b]),on=!sel||(act.has(a)&&act.has(b));s+=`<path d="M${x1+200} ${y1+11}C${x1+230} ${y1+11} ${x2-30} ${y2+11} ${x2} ${y2+11}" fill="none" stroke="${v<0?'#aab3c3':COL[v]}" stroke-width="1.5" opacity="${on?.85:.08}"/>`});
 Object.values(idx).forEach(n=>{const[x,y]=pos(n);s+=`<g data-k="${esc(n.key)}" style="cursor:pointer" opacity="${!sel||act.has(n.key)?1:.25}"><rect x="${x}" y="${y}" width="200" height="22" rx="5" fill="#fff" stroke="${n.sev<0?'#aab3c3':COL[n.sev]}" stroke-width="2"/><text x="${x+8}" y="${y+15}">${esc(n.label.slice(0,32))}</text></g>`});
 $('#graph').innerHTML=s+'</svg>';
 $('#graph').querySelectorAll('g').forEach(g=>g.onclick=()=>{sel=sel==g.dataset.k?null:g.dataset.k;drawGraph(r)})}
const A='arn:aws:iam::111111111111:',S=(a,r='*')=>({Effect:'Allow',Action:a,Resource:r}),P=(...s)=>({Version:'2012-10-17',Statement:s});
const SAMPLE={UserDetailList:[
{UserName:'alice',Arn:A+'user/alice',GroupList:['Devs'],AttachedManagedPolicies:[{PolicyName:'AdminAll',PolicyArn:A+'policy/AdminAll'}],PasswordLastUsed:'2026-11-10T08:00:00Z'},
{UserName:'bob',Arn:A+'user/bob',GroupList:[],UserPolicyList:[{PolicyName:'s3-all',PolicyDocument:P(S('s3:*'))}],PasswordLastUsed:'2025-01-15T08:00:00Z'},
{UserName:'svc-ci',Arn:A+'user/svc-ci',GroupList:[],UserPolicyList:[{PolicyName:'ci-deploy',PolicyDocument:P(S(['iam:PassRole','lambda:CreateFunction','lambda:UpdateFunctionCode']))}]}],
GroupDetailList:[{GroupName:'Devs',Arn:A+'group/Devs',GroupPolicyList:[{PolicyName:'dev-ec2',PolicyDocument:P(S('ec2:*'))}]}],
RoleDetailList:[
{RoleName:'AppRole',Arn:A+'role/AppRole',AssumeRolePolicyDocument:P({Effect:'Allow',Principal:{Service:'ec2.amazonaws.com'},Action:'sts:AssumeRole'}),RolePolicyList:[{PolicyName:'read-bucket',PolicyDocument:P(S('s3:GetObject','arn:aws:s3:::app-data/*'))}],RoleLastUsed:{LastUsedDate:'2026-11-14T00:00:00Z'}},
{RoleName:'VendorAccess',Arn:A+'role/VendorAccess',AssumeRolePolicyDocument:P({Effect:'Allow',Principal:{AWS:'arn:aws:iam::999999999999:root'},Action:'sts:AssumeRole'}),RolePolicyList:[{PolicyName:'vendor-s3',PolicyDocument:P(S(['s3:GetObject','s3:PutObject']))}],RoleLastUsed:{LastUsedDate:'2026-10-01T00:00:00Z'}},
{RoleName:'OpenRole',Arn:A+'role/OpenRole',AssumeRolePolicyDocument:P({Effect:'Allow',Principal:{AWS:'*'},Action:'sts:AssumeRole'}),RolePolicyList:[{PolicyName:'ddb-all',PolicyDocument:P(S('dynamodb:*'))}],RoleLastUsed:{LastUsedDate:'2026-11-01T00:00:00Z'}},
{RoleName:'LegacyRole',Arn:A+'role/LegacyRole',AssumeRolePolicyDocument:P({Effect:'Allow',Principal:{Service:'lambda.amazonaws.com'},Action:'sts:AssumeRole'}),RolePolicyList:[{PolicyName:'old-sqs',PolicyDocument:P(S('sqs:SendMessage','arn:aws:sqs:us-east-1:111111111111:q'))}],RoleLastUsed:{}}],
Policies:[{PolicyName:'AdminAll',Arn:A+'policy/AdminAll',PolicyVersionList:[{IsDefaultVersion:true,Document:P(S('*'))}]}]};
function run(){try{const d=JSON.parse($('#in').value);render(analyze(d));$('#err').textContent=''}catch(e){$('#err').textContent='Could not analyze: '+e.message}}
$('#load').onclick=()=>{$('#in').value=JSON.stringify(SAMPLE,null,1);run()};
$('#file').onchange=async e=>{$('#in').value=await e.target.files[0].text();run()};
$('#go').onclick=run;
$('#exp').onclick=()=>{if(!window.R)return;const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(R.F,null,2)],{type:'application/json'}));a.download='iam-findings.json';a.click()};
document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tabs button').forEach(x=>x.classList.toggle('on',x==b));['find','graph','docs'].forEach(t=>$('#t-'+t).hidden=t!=b.dataset.t)});
$('#load').click();
