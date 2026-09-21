"""Render this presentation's native template geometry for offline inspection.

Usage: python3 render_template.py input.pptx [output_dir] --slides 2,4
The PPTX is never modified. This is a geometry/font preview, not PowerPoint's
layout engine. Unsupported constructs and font substitutions are reported.
"""
from __future__ import annotations

import argparse
from functools import lru_cache
from io import BytesIO
import json
import math
from pathlib import Path
import re

from PIL import Image, ImageChops, ImageDraw, ImageFont
from pptx import Presentation

NS = {"a": "http://schemas.openxmlformats.org/drawingml/2006/main",
      "p": "http://schemas.openxmlformats.org/presentationml/2006/main",
      "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
IDENTITY = (1., 0., 0., 1., 0., 0.)
FONT_DIR = Path('/Users/adieu/Library/Fonts')


def find(node, path):
    return None if node is None else node.find(path, NS)


def tag(node):
    return node.tag.rsplit('}', 1)[-1]


def number(node, key, default=0):
    return float(node.get(key, default)) if node is not None else float(default)


def multiply(m, n):
    a,b,c,d,e,f=m; A,B,C,D,E,F=n
    return (a*A+c*B,b*A+d*B,a*C+c*D,b*C+d*D,a*E+c*F+e,b*E+d*F+f)


def point(m, x, y):
    a,b,c,d,e,f=m
    return (a*x+c*y+e,b*x+d*y+f)


def translate(x, y):
    return (1.,0.,0.,1.,x,y)


def around_center(xfrm, width, height):
    angle=math.radians(number(xfrm,'rot')/60000)
    fx=-1 if xfrm.get('flipH') in ('1','true') else 1
    fy=-1 if xfrm.get('flipV') in ('1','true') else 1
    rotation=(math.cos(angle)*fx,math.sin(angle)*fx,
              -math.sin(angle)*fy,math.cos(angle)*fy,0.,0.)
    return multiply(translate(width/2,height/2),
                    multiply(rotation,translate(-width/2,-height/2)))


def shape_transform(xfrm, parent):
    off=find(xfrm,'a:off'); ext=find(xfrm,'a:ext')
    width=number(ext,'cx'); height=number(ext,'cy')
    m=multiply(parent,translate(number(off,'x'),number(off,'y')))
    if xfrm is not None:
        m=multiply(m,around_center(xfrm,width,height))
    return m,width,height


def group_transform(xfrm, parent):
    m,width,height=shape_transform(xfrm,parent)
    off=find(xfrm,'a:chOff'); ext=find(xfrm,'a:chExt')
    sx=width/number(ext,'cx',width or 1) if number(ext,'cx',width or 1) else 1
    sy=height/number(ext,'cy',height or 1) if number(ext,'cy',height or 1) else 1
    return multiply(m,(sx,0.,0.,sy,-number(off,'x')*sx,-number(off,'y')*sy))


@lru_cache(maxsize=256)
def get_font(name, size, bold=False, italic=False):
    low=(name or '').lower().replace(' ','')
    substitution=None
    if '210' in low or '옴니' in low or 'omni' in low:
        # This installed font triggers a FreeType stack overflow on Hangul.
        path=FONT_DIR/'JASOSansBold.otf'
        substitution='210 옴니고딕 → JASO Sans Bold (installed font FreeType error)'
    elif 'jaso' in low or '자소' in low:
        path=FONT_DIR/('JASOSansBold.otf' if bold or 'bold' in low else 'JASOSans.otf')
    elif 'poppins' in low:
        path=FONT_DIR/'PoppinsMedium.ttf'
    elif 'aptos' in low:
        path=Path('/Applications/Microsoft PowerPoint.app/Contents/Resources/DFonts')/('Aptos-Bold.ttf' if bold else 'Aptos.ttf')
    else:
        path=Path('/System/Library/Fonts/AppleSDGothicNeo.ttc')
    if not path.exists():
        substitution=f'{name} → Apple SD Gothic Neo (font unavailable)'
        path=Path('/System/Library/Fonts/AppleSDGothicNeo.ttc')
    index=6 if path.suffix=='.ttc' and bold else 0
    return ImageFont.truetype(str(path),max(1,int(round(size))),index=index),substitution


class Renderer:
    def __init__(self, presentation, width=1800):
        self.deck=presentation
        self.scale=width/presentation.slide_width
        self.size=(width,round(presentation.slide_height*self.scale))
        self.warnings=set()
        self.overflow=[]
        self.theme={'dk1':'000000','lt1':'FFFFFF','dk2':'333333','lt2':'FAF9F9',
                    'accent1':'4F785F','accent2':'A39D9D','tx1':'333333','bg1':'FFFFFF'}

    def color(self,node,default=None):
        if node is None: return default
        if tag(node) in ('solidFill','ln','bgPr'):
            if find(node,'a:noFill') is not None: return None
            solid=find(node,'a:solidFill')
            if solid is not None: node=solid
            child=next((c for c in node if tag(c).endswith('Clr')),None)
        else: child=node
        if child is None:return default
        kind=tag(child)
        if kind=='srgbClr': value=child.get('val','333333')
        elif kind=='sysClr':value=child.get('lastClr','333333')
        elif kind=='schemeClr':value=self.theme.get(child.get('val'),'333333')
        else:return default
        channels=[int(value[i:i+2],16) for i in (0,2,4)]
        alpha=255
        for modifier in child:
            amount=number(modifier,'val')/100000
            if tag(modifier)=='alpha':alpha=round(amount*255)
            elif tag(modifier)=='tint':channels=[round(v+(255-v)*amount) for v in channels]
            elif tag(modifier) in ('shade','lumMod'):channels=[round(v*amount) for v in channels]
            elif tag(modifier)=='lumOff':channels=[min(255,round(v+255*amount)) for v in channels]
        return tuple(channels+[alpha])

    def render(self,slide,index):
        self.slide=slide;self.index=index
        background=self.color(find(slide._element,'p:cSld/p:bg/p:bgPr'),(250,249,249,255))
        self.image=Image.new('RGBA',self.size,background)
        for element in slide._element.spTree:
            self.element(element,(self.scale,0.,0.,self.scale,0.,0.))
        return self.image.convert('RGB')

    def element(self,element,parent):
        kind=tag(element)
        if kind=='grpSp':
            m=group_transform(find(element,'p:grpSpPr/a:xfrm'),parent)
            for child in element:
                if tag(child) not in ('nvGrpSpPr','grpSpPr'):self.element(child,m)
            return
        if kind not in ('sp','pic','cxnSp'):return
        props=find(element,'p:spPr')
        xfrm=find(props,'a:xfrm')
        if xfrm is None:return
        m,width,height=shape_transform(xfrm,parent)
        paths=self.paths(props,width,height)
        fill=self.color(find(props,'a:solidFill'))
        ln=find(props,'a:ln');stroke=self.color(ln)
        # A line without a direct color can inherit its style color.
        if ln is not None and stroke is None and find(ln,'a:noFill') is None:
            stroke=self.color(find(element,'p:style/a:lnRef/a:schemeClr'))
        line_width=max(1,round(number(ln,'w',12700)*math.hypot(m[0],m[1])))
        draw=ImageDraw.Draw(self.image)
        polygons=[]
        for pts,closed,allowfill,allowstroke in paths:
            mapped=[point(m,*p) for p in pts]
            polygons.append((mapped,closed,allowfill))
            if fill and closed and allowfill and len(mapped)>2:
                draw.polygon(mapped,fill=fill)
            if stroke and allowstroke and len(mapped)>1:
                draw.line(mapped+([mapped[0]] if closed else []),fill=stroke,width=line_width,joint='curve')
        if kind=='cxnSp' and not paths:
            draw.line([point(m,0,0),point(m,width,height)],fill=stroke or (200,200,200,255),width=line_width)
        blip=find(element,'p:blipFill') if kind=='pic' else find(props,'a:blipFill')
        if blip is not None:self.picture(blip,m,width,height,polygons)
        body=find(element,'p:txBody')
        if body is not None:self.text(body,m,width,height,element)

    def paths(self,props,width,height):
        custom=find(props,'a:custGeom/a:pathLst')
        if custom is not None:
            result=[]
            for path in custom:
                sx=width/number(path,'w',width or 1);sy=height/number(path,'h',height or 1)
                current=[];last=(0.,0.)
                flags=(path.get('fill')!='none',path.get('stroke') not in ('0','false'))
                for command in path:
                    kind=tag(command)
                    pts=[(number(p,'x')*sx,number(p,'y')*sy) for p in command if tag(p)=='pt']
                    if kind=='moveTo':
                        if current:result.append((current,False,*flags))
                        current=[pts[0]];last=pts[0]
                    elif kind=='lnTo':current.extend(pts);last=pts[-1]
                    elif kind in ('cubicBezTo','quadBezTo'):
                        p0=last
                        for step in range(1,25):
                            t=step/24;u=1-t
                            if kind=='cubicBezTo':
                                p1,p2,p3=pts
                                q=tuple(u**3*p0[j]+3*u*u*t*p1[j]+3*u*t*t*p2[j]+t**3*p3[j] for j in (0,1))
                            else:
                                p1,p2=pts;q=tuple(u*u*p0[j]+2*u*t*p1[j]+t*t*p2[j] for j in (0,1))
                            current.append(q)
                        last=pts[-1]
                    elif kind=='close':
                        if current:result.append((current,True,*flags));current=[]
                    else:self.warnings.add(f'Unsupported path command: {kind}')
                if current:result.append((current,False,*flags))
            return result
        preset=find(props,'a:prstGeom')
        if preset is None:return []
        kind=preset.get('prst','rect')
        if kind=='line':return [([(0,0),(width,height)],False,False,True)]
        if kind=='ellipse':
            points=[(width/2+width/2*math.cos(i*math.tau/100),height/2+height/2*math.sin(i*math.tau/100)) for i in range(100)]
        elif kind=='roundRect':
            gd=find(preset,'a:avLst/a:gd');radius=min(width,height)*.16667
            if gd is not None:
                try:radius=min(width,height)*float(gd.get('fmla','val 16667').split()[-1])/100000
                except ValueError:pass
            points=[]
            for cx,cy,start in [(width-radius,radius,-90),(width-radius,height-radius,0),(radius,height-radius,90),(radius,radius,180)]:
                points += [(cx+radius*math.cos(math.radians(start+i*90/16)),cy+radius*math.sin(math.radians(start+i*90/16))) for i in range(17)]
        else:
            points=[(0,0),(width,0),(width,height),(0,height)]
            if kind!='rect':self.warnings.add(f'Preset approximated as rectangle: {kind}')
        return [(points,True,True,True)]

    def picture(self,blip,m,width,height,polygons):
        reference=find(blip,'a:blip')
        rid=reference.get('{'+NS['r']+'}embed') if reference is not None else None
        if not rid:return
        try:source=Image.open(BytesIO(self.slide.part.related_part(rid).blob)).convert('RGBA')
        except Exception as exc:
            self.warnings.add(f'Image {rid}: {exc}');return
        crop=find(blip,'a:srcRect')
        if crop is not None:
            iw,ih=source.size
            source=source.crop((round(iw*number(crop,'l')/100000),round(ih*number(crop,'t')/100000),
                                round(iw*(1-number(crop,'r')/100000)),round(ih*(1-number(crop,'b')/100000))))
        iw,ih=source.size
        if not width or not height or not iw or not ih:return
        mapping=multiply(m,(width/iw,0.,0.,height/ih,0.,0.))
        a,b,c,d,e,f=mapping;det=a*d-b*c
        if abs(det)<1e-12:return
        inverse=(d/det,-c/det,(c*f-d*e)/det,-b/det,a/det,(b*e-a*f)/det)
        painted=source.transform(self.size,Image.Transform.AFFINE,inverse,resample=Image.Resampling.BICUBIC)
        if polygons:
            mask=Image.new('L',self.size,0);draw=ImageDraw.Draw(mask)
            for pts,closed,allowfill in polygons:
                if closed and len(pts)>2:draw.polygon(pts,fill=255)
            painted.putalpha(ImageChops.multiply(painted.getchannel('A'),mask))
        self.image.alpha_composite(painted)

    def run_style(self,rpr,default,scale):
        def attribute(key,fallback):
            return rpr.get(key,default.get(key,fallback) if default is not None else fallback) if rpr is not None else (default.get(key,fallback) if default is not None else fallback)
        face=find(rpr,'a:ea')
        if face is None:face=find(rpr,'a:latin')
        if face is None:face=find(default,'a:ea')
        if face is None:face=find(default,'a:latin')
        name=face.get('typeface') if face is not None else 'JASO Sans'
        bold=attribute('b','false') in ('1','true') or 'bold' in name.lower()
        size=float(attribute('sz','2400'))/100*12700*scale
        font,warning=get_font(name,size,bold,attribute('i','false') in ('1','true'))
        if warning:self.warnings.add(warning)
        color=self.color(find(rpr,'a:solidFill')) or self.color(find(default,'a:solidFill')) or (51,51,51,255)
        spacing=float(attribute('spc','0'))/100*12700*scale
        return {'font':font,'size':size,'color':color,'spacing':spacing}

    def text(self,body,m,width,height,element):
        bodypr=find(body,'a:bodyPr')
        sx=math.hypot(m[0],m[1]);sy=math.hypot(m[2],m[3])
        # Text is rendered on its own local surface, then transformed with its
        # shape, so nested groups, shape rotations, and flips remain coherent.
        left=number(bodypr,'lIns',91440)*sx;right=number(bodypr,'rIns',91440)*sx
        top=number(bodypr,'tIns',45720)*sy;bottom=number(bodypr,'bIns',45720)*sy
        boxw=width*sx;boxh=height*sy;available=max(1,boxw-left-right)
        wrap=bodypr is None or bodypr.get('wrap')!='none'
        lines=[]
        for paragraph in body.findall('a:p',NS):
            ppr=find(paragraph,'a:pPr');default=find(ppr,'a:defRPr')
            if default is None:default=find(body,'a:lstStyle/a:lvl1pPr/a:defRPr')
            alignment=ppr.get('algn','l') if ppr is not None else 'l'
            runs=[]
            for run in paragraph:
                kind=tag(run)
                if kind=='br':runs.append(('\n',self.run_style(find(run,'a:rPr'),default,sy)))
                elif kind in ('r','fld'):
                    style=self.run_style(find(run,'a:rPr'),default,sy)
                    runs.append(((find(run,'a:t').text or '') if find(run,'a:t') is not None else '',style))
            if not runs:continue
            charlines=[[]];length=0
            for value,style in runs:
                for char in value.replace('\v','\n'):
                    if char=='\n':charlines.append([]);length=0;continue
                    advance=float(style['font'].getlength(char))+style['spacing']
                    if wrap and length+advance>available+1 and charlines[-1]:
                        # Break at whitespace for Latin words, otherwise permit
                        # character-level Korean line wrapping as in PowerPoint.
                        previous=charlines[-1]
                        lastspace=next((i for i in range(len(previous)-1,-1,-1) if previous[i][0].isspace()),-1)
                        if lastspace>=0 and char.isascii() and char.isalnum():
                            tail=previous[lastspace+1:];charlines[-1]=previous[:lastspace]
                            charlines.append(tail);length=sum(c[2] for c in tail)
                        else:charlines.append([]);length=0
                        if char.isspace():continue
                    charlines[-1].append((char,style,advance));length+=advance
            before=self.par_space(find(ppr,'a:spcBef'),runs[0][1]['size'],sy)
            after=self.par_space(find(ppr,'a:spcAft'),runs[0][1]['size'],sy)
            for i,chars in enumerate(charlines):
                size=max((style['size'] for _,style,_ in chars),default=runs[0][1]['size'])
                lineheight=self.par_space(find(ppr,'a:lnSpc'),size,sy) or size*1.2
                ascent=max((style['font'].getmetrics()[0] for _,style,_ in chars),default=size)
                descent=max((style['font'].getmetrics()[1] for _,style,_ in chars),default=size*.2)
                lines.append({'chars':chars,'width':sum(c[2] for c in chars),
                              'height':lineheight,'before':before if i==0 else 0,
                              'after':after if i==len(charlines)-1 else 0,
                              'align':alignment,'ascent':ascent,'descent':descent})
        if not lines:return
        total=sum(line['height']+line['before']+line['after'] for line in lines)
        anch=bodypr.get('anchor','t') if bodypr is not None else 't'
        yy=top+((boxh-top-bottom-total)/2 if anch=='ctr' else boxh-top-bottom-total if anch=='b' else 0)
        # Extra transparent margin preserves legitimate glyph overhang rather
        # than silently clipping it to the stored PowerPoint shape extent.
        padding=32
        surface=Image.new('RGBA',(max(1,math.ceil(boxw)+2*padding),max(1,math.ceil(max(boxh,top+total))+2*padding)),(0,0,0,0))
        draw=ImageDraw.Draw(surface)
        text=''.join(c[0] for line in lines for c in line['chars'])
        for line in lines:
            yy+=line['before'];xx=left
            if line['align']=='ctr':xx+=(available-line['width'])/2
            elif line['align']=='r':xx+=available-line['width']
            if line['width']>available+3:self.overflow.append({'slide':self.index,'kind':'width','text':text[:160]})
            # PowerPoint places the glyphs near the top of each line box while
            # explicit lnSpc controls successive baseline distances.
            baseline=yy+line['ascent']
            for char,style,advance in line['chars']:
                draw.text((xx+padding,baseline+padding),char,font=style['font'],fill=style['color'],anchor='ls')
                xx+=advance
            yy+=line['height']+line['after']
        visible_height=(lines[-1]['ascent']+lines[-1]['descent'])
        if total-lines[-1]['height']+visible_height>boxh-top-bottom+5:
            self.overflow.append({'slide':self.index,'kind':'height','text':text[:160],
                                  'content_px':round(total,1),'box_px':round(boxh-top-bottom,1)})
        mapping=multiply(m,multiply((1/sx,0.,0.,1/sy,0.,0.),translate(-padding,-padding)))
        a,b,c,d,e,f=mapping;det=a*d-b*c
        if not det:return
        inverse=(d/det,-c/det,(c*f-d*e)/det,-b/det,a/det,(b*e-a*f)/det)
        layer=surface.transform(self.size,Image.Transform.AFFINE,inverse,resample=Image.Resampling.BICUBIC)
        self.image.alpha_composite(layer)

    @staticmethod
    def par_space(node,size,scale):
        value=find(node,'a:spcPts')
        if value is not None:return number(value,'val')/100*12700*scale
        value=find(node,'a:spcPct')
        if value is not None:return size*number(value,'val')/100000
        return 0


def selected_slides(value,count):
    if not value:return list(range(1,count+1))
    result=[]
    for item in re.split(r'[,\s]+',value):
        if not item:continue
        if '-' in item:
            low,high=map(int,item.split('-',1));result.extend(range(low,high+1))
        else:result.append(int(item))
    if any(i<1 or i>count for i in result):raise ValueError(f'Slide number must be between 1 and {count}')
    return list(dict.fromkeys(result))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pptx',type=Path)
    parser.add_argument('output_dir',nargs='?',type=Path)
    parser.add_argument('--slides',help='One-based indices, e.g. 2,4 or 1-4')
    parser.add_argument('--width',type=int,default=1800)
    args=parser.parse_args()
    output=args.output_dir or args.pptx.with_name(args.pptx.stem+'_preview')
    output.mkdir(parents=True,exist_ok=True)
    deck=Presentation(args.pptx);renderer=Renderer(deck,args.width)
    images=[];indices=selected_slides(args.slides,len(deck.slides))
    for index in indices:
        image=renderer.render(deck.slides[index-1],index)
        image.save(output/f'layout-{index}.png');images.append(image)
    thumb_width=890;thumb_height=round(renderer.size[1]*thumb_width/renderer.size[0])
    rows=math.ceil(len(images)/2);sheet=Image.new('RGB',(1840,20+rows*(thumb_height+30)),(200,200,200))
    for i,image in enumerate(images):
        thumb=image.resize((thumb_width,thumb_height),Image.Resampling.LANCZOS)
        sheet.paste(thumb,(20+(i%2)*910,20+(i//2)*(thumb_height+30)))
    sheet.save(output/'layout-review.png')
    report={'input':str(args.pptx.resolve()),'slides':indices,'width':args.width,
            'warnings':sorted(renderer.warnings),'potential_text_overflow':renderer.overflow,
            'note':'Offline review only; not a pixel-equivalent PowerPoint render.'}
    (output/'render-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False,indent=2))
    print(output/'layout-review.png')


if __name__=='__main__':main()
