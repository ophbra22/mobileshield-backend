import { NextRequest } from 'next/server';
import PDFDocument from 'pdfkit';

export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
  const body = await req.json();
  const doc = new PDFDocument({ margin: 40 });
  const chunks: Buffer[] = [];
  doc.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
  doc.on('end', () => {});

  doc.fontSize(18).text('MobileShield AI - Scan Report', { align: 'right' });
  doc.moveDown();
  doc.fontSize(12);
  const fields = [
    ['URL', body.normalized_url],
    ['Domain', body.domain],
    ['Verdict', body.verdict],
    ['Risk Score', body.risk_score],
    ['Confidence', body.confidence],
    ['Redirect Hops', body.redirect_hops],
    ['Final URL', body.final_url || 'N/A'],
  ];
  fields.forEach(([k, v]) => {
    doc.text(`${k}: ${v}`, { align: 'right' });
  });
  doc.moveDown();
  doc.text('Reasons:', { align: 'right', underline: true });
  (body.reasons || []).forEach((r: string) => doc.text(`- ${r}`, { align: 'right' }));
  doc.moveDown();
  doc.text('Signals:', { align: 'right', underline: true });
  doc.fontSize(9).text(JSON.stringify(body.signals, null, 2), { align: 'right' });
  doc.end();

  const pdf = Buffer.concat(chunks);
  return new Response(pdf, {
    status: 200,
    headers: {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="mobileshield_scan.pdf"`,
    },
  });
}
