"""Tell people when a scheduled scan's result changed.

A nightly scan nobody reads is the same as no scan. After each queued scan the
new report is compared with the previous one of the same target (zanjir.baseline
matches findings by fingerprint), and when something changed -- new findings,
findings that disappeared, or a different outcome such as `failed` -- a short
message goes to every configured channel: a generic JSON webhook, Slack, email.

What a message contains, and what it never does:
  - stage, target, report id, both outcomes, the counts, up to five new
    findings (rule, severity, subject) -- enough to decide whether to look;
  - never secret values, code, evidence bodies or credentials: the same data a
    report summary already shows on the dashboard.
"Gone" is reported as gone, never as fixed (see baseline.py).
"""
import datetime
import json
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage

from . import nettrust, settings

TIMEOUT = 10
TOP = 5


def previous_report(stage, report):
    """The newest earlier report of the same target (any final state), or None."""
    from . import baseline
    target = baseline.target_of(report, stage)
    passed = False
    for row in baseline.history_rows(stage):
        if row.get('id') == report.get('id'):
            passed = True
            continue
        if passed and baseline.target_of(row, stage) == target and row.get('state') not in ('queued', 'running'):
            try:
                return baseline.read_report(stage, row['id'])
            except (OSError, ValueError):
                return None
    return None


def change(stage, report):
    """{'changed', 'first', 'counts', 'new', 'states', ...} for `report` against the one before it."""
    from . import baseline
    before = previous_report(stage, report)
    if before is None:
        diff = baseline.diff({'state': ''}, report)
        return {'changed': True, 'first': True, 'counts': diff['counts'], 'new': diff['new'][:TOP],
                'before_id': None, 'before_state': None, 'after_state': baseline.state_of(report),
                'warnings': []}
    diff = baseline.diff(before, report)
    changed = bool(diff['counts']['new'] or diff['counts']['gone']) or diff['before_state'] != diff['after_state']
    return {'changed': changed, 'first': False, 'counts': diff['counts'], 'new': diff['new'][:TOP],
            'before_id': diff['before'], 'before_state': diff['before_state'], 'after_state': diff['after_state'],
            'warnings': diff['warnings']}


def event_for(job, report, delta):
    return {'event': 'threatchain.scan_result_changed' if delta['changed'] else 'threatchain.scan_finished',
            'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'kind': job['kind'], 'target': job.get('target') or '', 'job_id': job['id'],
            'schedule_id': job.get('schedule_id'), 'report_id': report.get('id'),
            'state': delta['after_state'], 'previous_state': delta['before_state'],
            'previous_report_id': delta['before_id'], 'first_scan': delta['first'],
            'counts': delta['counts'], 'findings_total': report.get('count', len(report.get('findings') or [])),
            'new_findings': [{k: item.get(k) for k in ('rule_id', 'severity', 'subject', 'title')} for item in delta['new']],
            'warnings': delta['warnings'],
            'note': 'Yo‘qolgan topilma tuzatilgan degani emas (qamrov o‘zgargan bo‘lishi mumkin).'}


def text_for(event):
    head = (f"ThreatChain · {event['kind']} · {event['target'] or 'umumiy'}: "
            f"{event['previous_state'] or '—'} → {event['state']}")
    counts = event['counts']
    lines = [head,
             ('Birinchi skan (solishtirish uchun asos yo‘q). ' if event['first_scan'] else '') +
             f"Yangi: {counts['new']}, yo‘qolgan: {counts['gone']}, o‘zgarmagan: {counts['unchanged']}. "
             f"Jami topilma: {event['findings_total']}. Hisobot: {event['report_id']}"]
    for item in event['new_findings']:
        lines.append(f"  + [{item.get('severity') or '?'}] {item.get('rule_id') or ''} {item.get('subject') or ''}".rstrip())
    lines += ['  ! ' + warning for warning in event['warnings']]
    lines.append(event['note'])
    return '\n'.join(lines)


def _post_json(url, body):
    request = urllib.request.Request(url, data=json.dumps(body, ensure_ascii=False).encode('utf-8'),
                                     headers={'Content-Type': 'application/json', 'User-Agent': 'ThreatChain/0.7'},
                                     method='POST')
    opener = urllib.request.build_opener(nettrust.proxy_handler(),
                                         urllib.request.HTTPSHandler(context=nettrust.ssl_context()))
    with opener.open(request, timeout=TIMEOUT) as response:
        response.read(4096)
        return response.status


def _send_email(config, subject, text):
    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = config['sender']
    message['To'] = ', '.join(config['recipients'])
    message.set_content(text)
    context = nettrust.ssl_context()
    if config['security'] == 'ssl':
        server = smtplib.SMTP_SSL(config['host'], config['port'], timeout=TIMEOUT, context=context)
    else:
        server = smtplib.SMTP(config['host'], config['port'], timeout=TIMEOUT)
    with server:
        if config['security'] == 'starttls':
            server.starttls(context=context)
        if config.get('username'):
            server.login(config['username'], config.get('password') or '')
        server.send_message(message)


def deliver(event, config=None):
    """Send `event` to every configured channel; one result per channel, no secret in it."""
    config = settings.notifications() if config is None else config
    text = text_for(event)
    results = []
    channels = [('webhook', lambda: _post_json(config['webhook_url'], event)) if config.get('webhook_url') else None,
                ('slack', lambda: _post_json(config['slack_webhook_url'], {'text': text})) if config.get('slack_webhook_url') else None,
                ('email', lambda: _send_email(config['email'], text.splitlines()[0], text)) if config.get('email') else None]
    for name, send in filter(None, channels):
        try:
            send()
            results.append({'channel': name, 'ok': True})
        except (OSError, smtplib.SMTPException, ssl.SSLError, ValueError) as error:
            # The error type and a short reason only: SMTP and HTTP errors can
            # echo the URL (which holds the Slack/webhook secret) back.
            reason = getattr(error, 'code', None) or getattr(error, 'smtp_code', None) or type(error).__name__
            results.append({'channel': name, 'ok': False, 'error': str(reason)[:80]})
    return results


def test_event():
    return {'event': 'threatchain.test', 'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'kind': 'test', 'target': '', 'job_id': None, 'schedule_id': None, 'report_id': None,
            'state': 'test', 'previous_state': None, 'previous_report_id': None, 'first_scan': False,
            'counts': {'new': 0, 'gone': 0, 'unchanged': 0}, 'findings_total': 0, 'new_findings': [],
            'warnings': [], 'note': 'Sinov xabari: kanal sozlamasi ishlayapti.'}
