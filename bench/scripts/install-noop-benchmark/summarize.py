import hashlib,json,math,statistics
from pathlib import Path
root=Path(__file__).parent
summary=[]
parity=[]
for fixture in ['t3','vite-react','native-sharp','nest']:
 directory=Path(json.loads((root/f'bare-{fixture}-100.json').read_text())['output'])
 rows=json.loads((directory/'rows.json').read_text())
 assert len(rows)==600
 for scenario in sorted({r['scenario'] for r in rows}):
  for variant in ['baseline','candidate','bun']:
   group=[r for r in rows if r['scenario']==scenario and r['variant']==variant]
   assert len(group)==100 and all(r['ok'] and r['verification']['ok'] for r in group)
   assert sorted(r['sample'] for r in group)==list(range(1,101))
   for sample in range(1,101):
    artifact=directory/'artifacts'/scenario/variant/str(sample)
    assert (artifact/'selected-packages.json').is_file()
    if variant!='bun': assert (artifact/'lpm.lock').is_file()
   if variant=='candidate': assert all(r['compact_noop'] for r in group)
   result={'fixture':fixture,'scenario':scenario,'variant':variant,'n':len(group)}
   for metric in ['wall_ms','max_rss_bytes']:
    values=sorted(r[metric] for r in group)
    result[metric]={'median':statistics.median(values),'p95':values[math.ceil(len(values)*.95)-1],'max':max(values),'min':min(values)}
   summary.append(result)
  baseline=sorted((r for r in rows if r['scenario']==scenario and r['variant']=='baseline'),key=lambda r:r['sample'])
  candidate=sorted((r for r in rows if r['scenario']==scenario and r['variant']=='candidate'),key=lambda r:r['sample'])
  inventories={}
  for variant in ['baseline','candidate','bun']:
   inventories[variant]={hashlib.sha256(p.read_bytes()).hexdigest() for p in (directory/'artifacts'/scenario/variant).glob('*/selected-packages.json')}
   assert len(inventories[variant])==1
  assert inventories['baseline']==inventories['candidate']==inventories['bun']
  locks={v:{hashlib.sha256(p.read_bytes()).hexdigest() for p in (directory/'artifacts'/scenario/v).glob('*/lpm.lock')} for v in ['baseline','candidate']}
  assert len(locks['baseline'])==1 and locks['baseline']==locks['candidate']
  parity.append({'fixture':fixture,'scenario':scenario,'inventory_sha256':{v:list(hashes) for v,hashes in inventories.items()},'lpm_lock_sha256':list(locks['baseline'])[0],'candidate_wins':sum(c['wall_ms']<b['wall_ms'] for b,c in zip(baseline,candidate)),'paired_median_delta_ms':statistics.median(c['wall_ms']-b['wall_ms'] for b,c in zip(baseline,candidate))})
(root/'bare-summary.json').write_text(json.dumps({'quantile':'nearest rank','rows':summary,'parity':parity},indent=2)+'\n')
for row in summary:
 print(row['fixture'],row['scenario'],row['variant'],row['wall_ms'],'rss median MiB',round(row['max_rss_bytes']['median']/1024**2,2))
