from pathlib import Path
import json,csv,hashlib,collections,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'data'/'event_level'
canon=lambda o:json.dumps(o,sort_keys=True,separators=(',',':')).encode('utf-8')
hashb=lambda b:hashlib.sha256(b).digest()
H=lambda b:hashlib.sha256(b).hexdigest()
readl=lambda p:[json.loads(x) for x in p.read_text().splitlines()]
def sigok(pk,sig,data):
 try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(bytes.fromhex(sig),data);return True
 except Exception:return False
def root(leaves):
 if not leaves:return hashb(b'')
 if len(leaves)==1:return leaves[0]
 k=1<<((len(leaves)-1).bit_length()-1)
 return hashb(b'\x01'+root(leaves[:k])+root(leaves[k:]))
def verify_inclusion(leaf,index,size,path):
 fn=index;sn=size-1;r=leaf
 for s in path:
  if sn==0:return None
  p=bytes.fromhex(s)
  if fn&1 or fn==sn:
   r=hashb(b'\x01'+p+r)
   while fn and not fn&1:fn>>=1;sn>>=1
  else:r=hashb(b'\x01'+r+p)
  fn>>=1;sn>>=1
 return r.hex() if sn==0 else None
start=time.monotonic(); total=collections.Counter(); reports=[];fail=[]
for run in sorted((BASE/'runs').iterdir()):
 t=json.loads((run/'trust_anchors.json').read_text());keys={k['key_id']:k for k in t['keys']}; heads=json.loads((run/'heads.json').read_text()); hd={h['size']:h for h in heads};logs=readl(run/'log.jsonl'); receipts=readl(run/'receipts.jsonl');rec={(r['dt'],r['seq']):r for r in receipts};leaves=[hashb(b'\x00'+canon(x)) for x in logs];c=collections.Counter();previous={};dtd=dict(t['initial_dtd']); seen={}; salts=set()
 def check(ok,label,context):
  c[label+'_checked']+=1
  if not ok:fail.append({'run':run.name,'check':label,'context':context});c[label+'_failed']+=1
 for h in heads:
  check(root(leaves[:h['size']]).hex()==h['root'],'merkle_root',h['size'])
  good=0
  for member,sig in h['signatures'].items():
   ok=sigok(t['member_keys'][member],sig,canon({'log':t['log_id'],'root':h['root'],'size':h['size']}));check(ok,'witness_signature',[h['size'],member]);good+=int(ok)
  check(good>=t['quorum'],'quorum',h['size'])
 for f in sorted((run/'evidence').glob('*.jsonl')):
  dt=None;seq=0;prev=None
  for entry in readl(f):
   p=entry['proof_object'];r=entry['record'];dt=p['dt'];ident=[dt,p['seq']]; c['objects']+=1
   check(H(r.encode('utf-8'))==p['pd'],'record_digest',ident)
   check(sigok(keys[p['kid']]['public_key'],p['sig'],canon({k:v for k,v in p.items() if k!='sig'})),'object_signature',ident)
   ts=p['tst'];check(ts['d']==p['pd'] and sigok(t['time_stamp_key'],ts['sig'],canon({k:v for k,v in ts.items() if k!='sig'})),'timestamp',ident)
   key=keys[p['kid']];check(key['valid_from_ns']<=ts['t'] and (key['revoked_at_ns'] is None or ts['t']<key['revoked_at_ns']),'key_status_at_record_timestamp',ident)
   check(p['seq']==seq+1 and p['prev']==prev,'predecessor_and_sequence',ident)
   commit=H(canon(p));seq=p['seq'];prev=commit
   check((dt,seq) not in seen,'unique_object_identifier',ident);seen[(dt,seq)]=commit
   check(len(bytes.fromhex(p['salt']))==16 and p['salt'] not in salts,'salt_length_and_uniqueness',ident);salts.add(p['salt'])
   record=json.loads(r)
   if p['cat']=='dtd_update':
    dtd[dt]=record['metadata']['dtd_version'];check(p['dtd']==dtd[dt] and record['payload']['version']=='dtd-v'+str(dtd[dt]) and 'description' in record['payload'],'dtd_update_binding',ident)
   else:check(p['dtd']==dtd[dt],'dtd_state',ident)
   if p['cat']=='rejection':c['rejections']+=1
   rr=rec.get((dt,seq))
   if rr:
    c['anchored']+=1
    if p['cat']=='rejection':c['anchored_rejections']+=1
    log=logs[rr['index']];check(log=={'dt':dt,'seq':seq,'c':commit},'anchor_commitment',ident)
    check(verify_inclusion(hashb(b'\x00'+canon(log)),rr['index'],rr['size'],rr['path'])==hd[rr['size']]['root'],'receipt_inclusion',ident)
   else:
    c['without_receipt']+=1
    if p['cat']=='rejection':c['unanchored_rejections']+=1
  if dt is not None:previous[dt]={'seq':seq,'commitment':prev}
 check(len(rec)==len(receipts),'receipt_identifier_uniqueness','all')
 check(len({(x['dt'],x['seq']) for x in logs})==len(logs),'log_identifier_uniqueness','all')
 check(len(rec)==len(logs),'receipt_log_count','all')
 reports.append({'run':run.name,'counts':dict(c),'last_heads':previous,'global_head_count':len(heads),'latest_head_size':heads[-1]['size']});total.update(c)
out={'source':'Read-only independent verification of saved artifacts, not execution of original verifier or simulation','canonicalization':'json.dumps(sort_keys=True,separators=(comma,colon)), UTF-8','timestamp_scope':'pd=SHA256(record UTF-8), not signed proof envelope','total':dict(total),'failures':fail,'runs':reports,'elapsed_seconds':round(time.monotonic()-start,3)}
(ROOT/'checks').mkdir(exist_ok=True)
(ROOT/'checks'/'saved_artifacts_verification.json').write_text(json.dumps(out,indent=2))
print(json.dumps({k:out[k] for k in ['total','failures','elapsed_seconds']},indent=2))
if fail:raise SystemExit(1)
