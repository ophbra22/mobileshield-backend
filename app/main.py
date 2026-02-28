"""
MobileShield AI backend.

Local run:
1) docker compose up --build
2) Open http://localhost:8000/docs
3) Call POST /admin/create-api-key with X-Admin-Token to mint an API key
4) Call POST /v1/analyze with X-API-Key header to scan URLs

Production checklist:
- Set DATABASE_URL, RATE_LIMIT_PER_MINUTE, CORS_ORIGINS (no wildcards), ENV=prod
- Disable admin by default: ENABLE_ADMIN=false (enable only for maintenance)
- If admin enabled, set ADMIN_TOKEN and optional ADMIN_ALLOW_IPS
- Rotate API keys by regenerating via admin endpoint (temp enable) and deactivating old keys
- Test /health and /readyz before exposing traffic; /v1/analyze requires X-API-Key
"""

import secrets
import time
from datetime import UTC, datetime
from io import BytesIO

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.base import RequestResponseEndpoint
from pydantic import BaseModel, Field
from sqlalchemy import desc, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.analysis import analyze_url
from app.auth import require_admin_ip_allowlist, require_admin_token, require_api_key
from app.db.database import Base, engine
from app.db.deps import get_db
from app.db.models import ApiKey, Scan
from app.settings import get_settings

settings = get_settings()
app = FastAPI(title='MobileShield AI')

origins = [origin.strip() for origin in settings.cors_origins.split(',') if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=['*'],
    allow_headers=['*'],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
        return response


class RequestIdLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get('X-Request-Id') or secrets.token_hex(8)
        start = time.perf_counter()
        response: Response
        try:
            response = await call_next(request)
        finally:
            duration_ms = int((time.perf_counter() - start) * 1000)
            # Avoid logging sensitive headers
            print(
                f"[req] id={request_id} method={request.method} path={request.url.path} "
                f"status={getattr(locals().get('response', None), 'status_code', 'n/a')} duration_ms={duration_ms}"
            )
        response.headers['X-Request-Id'] = request_id
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdLoggingMiddleware)


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048, pattern=r'^https?://.+')


class CreateApiKeyRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)


@app.on_event('startup')
def startup() -> None:
    last_error: Exception | None = None
    for attempt in range(1, 21):
        try:
            with engine.begin() as connection:
                connection.execute(text('SELECT 1'))
                Base.metadata.create_all(bind=engine)
                # lightweight migrations for new columns/tables
                connection.execute(
                    text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS breakdown JSON NOT NULL DEFAULT '[]'::json;")
                )
                connection.execute(
                    text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS reputation VARCHAR(32);")
                )
                connection.execute(
                    text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS reputation_score_hint INTEGER;")
                )
            return
        except OperationalError as exc:
            last_error = exc
            time.sleep(1)
    raise RuntimeError('Database did not become ready after 20 startup attempts.') from last_error


@app.get('/health')
def health() -> dict:
    return {'ok': True, 'service': settings.app_name}


@app.get('/readyz')
def readyz() -> dict:
    try:
        with engine.connect() as connection:
            connection.execute(text('SELECT 1'))
        return {'ready': True}
    except OperationalError:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail='database not ready')


@app.post('/admin/create-api-key')
def create_api_key(
    payload: CreateApiKeyRequest,
    _: None = Depends(require_admin_token),
    __: None = Depends(require_admin_ip_allowlist),
    db: Session = Depends(get_db),
) -> dict:
    api_key_value = f"ms_live_{secrets.token_urlsafe(32)}"
    record = ApiKey(name=payload.name, key=api_key_value, is_active=True)
    db.add(record)
    db.commit()
    return {'name': payload.name, 'api_key': api_key_value}


@app.post('/v1/analyze')
def analyze(
    payload: AnalyzeRequest,
    _: ApiKey = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict:
    try:
        result = analyze_url(payload.url, db)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    scan = Scan(
        normalized_url=result.normalized_url,
        domain=result.domain,
        final_url=result.final_url,
        risk_score=result.risk_score,
        verdict=result.verdict,
        confidence=result.confidence,
        reasons=result.reasons,
        signals=result.signals,
        breakdown=result.breakdown,
        reputation=result.reputation,
        reputation_score_hint=result.signals.get('domain_reputation', {}).get('score_hint') if result.signals else None,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    return {
        'scan_id': scan.id,
        'normalized_url': result.normalized_url,
        'domain': result.domain,
        'final_url': result.final_url,
        'redirect_hops': result.redirect_hops,
        'risk_score': result.risk_score,
        'verdict': result.verdict,
        'confidence': result.confidence,
        'reasons': result.reasons,
        'signals': result.signals,
        'breakdown': result.breakdown,
        'reputation': result.reputation,
    }


@app.get('/v1/scans')
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    _: ApiKey = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict:
    rows = db.execute(select(Scan).order_by(desc(Scan.created_at)).limit(limit)).scalars().all()
    items = [
        {
            'id': row.id,
            'created_at': row.created_at.astimezone(UTC).isoformat() if row.created_at else datetime.now(UTC).isoformat(),
            'normalized_url': row.normalized_url,
            'domain': row.domain,
            'final_url': row.final_url,
            'risk_score': row.risk_score,
            'verdict': row.verdict,
            'confidence': row.confidence,
            'reasons': row.reasons,
            'breakdown': row.breakdown,
            'reputation': row.reputation,
            'domain_reputation': row.signals.get('domain_reputation') if isinstance(row.signals, dict) else None,
        }
        for row in rows
    ]
    return {'items': items, 'count': len(items)}


@app.get('/v1/scans/{scan_id}/report.pdf')
def export_report(
    scan_id: int,
    _: ApiKey = Depends(require_api_key),
    db: Session = Depends(get_db),
):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Scan not found')

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elems = []

    elems.append(Paragraph('<b>MobileShield AI - Scan Report</b>', styles['Title']))
    elems.append(Spacer(1, 12))
    meta = [
        f"Scan ID: {scan.id}",
        f"Created: {scan.created_at.astimezone(UTC).isoformat() if scan.created_at else 'n/a'}",
        f"URL: {scan.normalized_url}",
        f"Domain: {scan.domain}",
        f"Final URL: {scan.final_url or 'n/a'}",
        f"Redirect hops: {scan.signals.get('redirect_hops', 0) if isinstance(scan.signals, dict) else ''}",
    ]
    elems.extend(Paragraph(line, styles['Normal']) for line in meta)
    elems.append(Spacer(1, 12))

    verdict_text = f"Verdict: {scan.verdict} | Score: {scan.risk_score} | Confidence: {scan.confidence}"
    elems.append(Paragraph(verdict_text, styles['Heading3']))
    elems.append(Spacer(1, 8))

    elems.append(Paragraph('<b>Reasons</b>', styles['Heading4']))
    if scan.reasons:
        for r in scan.reasons:
            elems.append(Paragraph(f"- {r}", styles['Normal']))
    else:
        elems.append(Paragraph('No reasons recorded.', styles['Normal']))
    elems.append(Spacer(1, 10))

    elems.append(Paragraph('<b>Risk Breakdown</b>', styles['Heading4']))
    breakdown_rows = [['Key', 'Points', 'Description']]
    for item in (scan.breakdown or []):
        breakdown_rows.append([item.get('key', ''), str(item.get('points', '')), item.get('description', '')])
    table = Table(breakdown_rows, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ]
        )
    )
    elems.append(table)
    elems.append(Spacer(1, 10))

    elems.append(Paragraph('<b>Signals</b>', styles['Heading4']))
    elems.append(Paragraph(f"{scan.signals}", styles['Normal']))

    doc.build(elems)
    buffer.seek(0)
    headers = {'Content-Disposition': f'attachment; filename="mobileshield_scan_{scan.id}.pdf"'}
    return StreamingResponse(buffer, media_type='application/pdf', headers=headers)
