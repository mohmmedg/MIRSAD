"""Optional notifications using administrator-configured destinations only."""
import os, json, urllib.request, smtplib
from email.message import EmailMessage

def notify(message: str) -> list[str]:
    sent=[]
    for name in ('SLACK_WEBHOOK_URL','DISCORD_WEBHOOK_URL'):
        url=os.getenv(name)
        if not url: continue
        try:
            data=json.dumps({'content':message} if 'DISCORD' in name else {'text':message}).encode()
            req=urllib.request.Request(url,data=data,headers={'Content-Type':'application/json'})
            with urllib.request.urlopen(req,timeout=5): pass
            sent.append(name)
        except Exception: pass
    host=os.getenv('SMTP_HOST'); to=os.getenv('NOTIFY_EMAIL_TO')
    if host and to:
        try:
            msg=EmailMessage(); msg['Subject']='Security Scanner notification'; msg['From']=os.getenv('SMTP_FROM','scanner@localhost'); msg['To']=to; msg.set_content(message)
            with smtplib.SMTP(host,int(os.getenv('SMTP_PORT','25')),timeout=5) as smtp:
                if os.getenv('SMTP_STARTTLS','false').lower()=='true': smtp.starttls()
                if os.getenv('SMTP_USER'): smtp.login(os.getenv('SMTP_USER'),os.getenv('SMTP_PASSWORD',''))
                smtp.send_message(msg)
            sent.append('email')
        except Exception: pass
    return sent
