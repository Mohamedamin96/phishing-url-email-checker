import re
import urllib.parse

SHORT=['bit.ly','tinyurl.com','t.co']
def level(s):
 return 'CRITICAL' if s>=75 else 'HIGH' if s>=50 else 'MEDIUM' if s>=25 else 'LOW'
def analyze_url(url):
 s=0;f=[]
 h=urllib.parse.urlparse(url).netloc.lower()
 if any(x in h for x in SHORT): s+=15; f.append('URL shortener detected')
 if 'xn--' in h: s+=30; f.append('Punycode detected')
 if re.fullmatch(r'\d+\.\d+\.\d+\.\d+',h): s+=30; f.append('IP address URL')
 if h.count('.')>3: s+=15; f.append('Excessive subdomains')
 return {'score':min(s,100),'risk_level':level(s),'findings':f}
def analyze_email(headers):
 t=headers.lower(); s=0; f=[]
 if 'spf=fail' in t: s+=20; f.append('SPF failed')
 if 'dkim=fail' in t: s+=20; f.append('DKIM failed')
 if 'dmarc=fail' in t: s+=25; f.append('DMARC failed')
 return {'score':min(s,100),'risk_level':level(s),'findings':f}
