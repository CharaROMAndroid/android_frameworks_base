from pathlib import Path
import subprocess, struct, json
from fontTools.ttLib import TTFont, newTable
from fontTools.ttLib.tables.ttProgram import Program
from PIL import Image,ImageDraw,ImageFont
import argparse,tempfile
parser=argparse.ArgumentParser()
parser.add_argument('sanitizer',type=Path)
parser.add_argument('hinted_font',type=Path)
args=parser.parse_args()
tmp=tempfile.TemporaryDirectory(prefix='font-dehint-test-')
work=Path(tmp.name);worker=args.sanitizer.resolve()
def run(src,dst,ok=True):
 p=subprocess.run([str(worker),str(src),str(dst)],capture_output=True,text=True)
 assert p.returncode==(0 if ok else 1),(str(src),p.returncode,p.stderr)
 assert not p.stderr,p.stderr
def check(path):
 f=TTFont(path,checkChecksums=2)
 assert not set(['fpgm','prep','cvt ','hdmx','LTSH','VDMX','cvar'])&set(f.keys())
 if 'glyf' in f:
  for g in f['glyf'].glyphs.values():
   g.expand(f['glyf'])
   assert not hasattr(g,'program') or not g.program.getBytecode()
  m=f['maxp']
  for key in ['maxSizeOfInstructions','maxFunctionDefs','maxInstructionDefs','maxStackElements','maxTwilightPoints','maxStorage']:assert getattr(m,key)==0,key
  assert m.maxZones==1
  assert f['head'].flags&0x1c==0
 data=path.read_bytes()
 assert sum(struct.unpack('>'+str(len(data)//4)+'I',data))&0xffffffff==0xB1B0AFBA
 for tag,t in f.reader.tables.items():
  b=data[t.offset:t.offset+t.length]
  if tag=='head': b=b[:8]+b'\0'*4+b[12:]
  b+=b'\0'*((-len(b))%4)
  assert sum(struct.unpack('>'+str(len(b)//4)+'I',b))&0xffffffff==t.checkSum,tag
 # Exercise downstream FreeType parsing, shaping-independent glyph rasterization.
 font=ImageFont.truetype(str(path),24)
 image=Image.new('L',(256,64))
 ImageDraw.Draw(image).text((0,0),'Hello Aa 123 é',font=font,fill=255)
 assert image.getbbox()
 return f
# Real hinted font with both simple and composite instruction paths.
src=args.hinted_font
f=TTFont(src)
simple=composite=0
for g in f['glyf'].glyphs.values():
 g.expand(f['glyf'])
 if hasattr(g,'program') and g.program.getBytecode():
  if g.isComposite():composite+=1
  else:simple+=1
assert simple and composite,(simple,composite)
out=work/'liberation-unhinted.ttf';run(src,out);clean=check(out)
assert len(clean.getGlyphOrder())==len(f.getGlyphOrder())
# Compare outline geometry for every glyph, not hinting-dependent raster pixels.
for name in f.getGlyphOrder():
 a=f['glyf'][name];b=clean['glyf'][name]
 assert a.numberOfContours==b.numberOfContours
 if a.numberOfContours>0:
  assert a.getCoordinates(f['glyf'])[0]==b.getCoordinates(clean['glyf'])[0],name
# Unknown hint bytecode must be stripped, not interpreted.
for g in f['glyf'].glyphs.values():
 if hasattr(g,'program') and g.program.getBytecode():g.program.fromBytecode(b'\x8f\xff\xff')
for tag in ['fpgm','prep']:f[tag].program.fromBytecode(b'\x8f\xff\xff')
# Add device hint tables, discarded even if their payload is malformed.
for tag in ['hdmx','LTSH','VDMX','cvar']:
 t=newTable('ZZZZ');t.tableTag=tag;t.data=b'\xff'*16;f[tag]=t
f.save(work/'poisoned-hints.ttf')
run(work/'poisoned-hints.ttf',work/'poisoned-clean.ttf');check(work/'poisoned-clean.ttf')
# Trigger bounding-box replacement while removing simple instructions.
# Disable FontTools bbox recalculation so OTS sees the deliberately small bbox.
bbox=TTFont(src);bbox.recalcBBoxes=False
for g in bbox['glyf'].glyphs.values():
 g.expand(bbox['glyf'])
 if g.numberOfContours>0 and hasattr(g,'program') and g.program.getBytecode():
  g.xMin=g.yMin=g.xMax=g.yMax=0
bbox.save(work/'bbox.ttf')
run(work/'bbox.ttf',work/'bbox-clean.ttf');check(work/'bbox-clean.ttf')
# A sole empty component is retained by OTS, and must lose its instruction flag.
from fontTools.ttLib.tables._g_l_y_f import Glyph, GlyphComponent
empty_case=TTFont(src)
empty_name=next(n for n in empty_case.getGlyphOrder() if empty_case['glyf'][n].numberOfContours==0)
composite_name=next(n for n in empty_case.getGlyphOrder() if empty_case['glyf'][n].isComposite())
g=Glyph();g.numberOfContours=-1
component=GlyphComponent();component.glyphName=empty_name
component.x=component.y=0;component.flags=0
g.components=[component];g.program=Program();g.program.fromBytecode(b'\x8f\xff')
g.xMin=g.yMin=g.xMax=g.yMax=0
empty_case['glyf'][composite_name]=g
empty_case.save(work/'lone-empty.ttf')
run(work/'lone-empty.ttf',work/'lone-empty-clean.ttf')
empty_out=check(work/'lone-empty-clean.ttf')
raw=empty_out.reader['glyf'];gid=empty_out.getGlyphID(composite_name)
offset=empty_out['loca'].locations[gid]
assert struct.unpack_from('>H',raw,offset+10)[0]&0x100==0
run(work/'lone-empty-clean.ttf',work/'lone-empty-twice.ttf')
assert (work/'lone-empty-clean.ttf').read_bytes()==(work/'lone-empty-twice.ttf').read_bytes()
result={'hinted_simple_glyphs'  :simple,'hinted_composite_glyphs':composite,'checksums_and_parse_render':'pass','geometry':'pass','poisoned_hint_tables_and_bytecode':'pass','repeat_sanitize':'pass','bbox_rewrite':'pass','lone_empty_composite':'pass'}
(work/'results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if True}))
