import os
import uuid
import logging
import hashlib
import time
import pandas as pd
from datetime import datetime
from io import BytesIO
from flask import Blueprint, request, jsonify, current_app, Response
from werkzeug.utils import secure_filename

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from core.pcap_parser import parse_pcap
from core.anomaly_engine import analyze_anomalies
from core.model_service import predict_traffic

logger = logging.getLogger('flask.app')
main_bp = Blueprint('main', __name__)


def allowed_file(filename):
    """Check if the file has a .pcap, .cap, or .pcapng extension."""
    ALLOWED_EXTENSIONS = {'pcap', 'cap', 'pcapng'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def cleanup_old_uploads(upload_folder, retention_hours):
    """Deletes files older than the retention period."""
    try:
        now = time.time()
        for filename in os.listdir(upload_folder):
            filepath = os.path.join(upload_folder, filename)
            if os.path.isfile(filepath):
                if os.stat(filepath).st_mtime < now - (retention_hours * 3600):
                    os.remove(filepath)
                    logger.info(f"Purged old upload: {filename}")
    except Exception as e:
        logger.error(f"Error during upload cleanup: {e}")


def _get_analysis_data(filename):
    """Helper to parse PCAP file, run rule-based anomaly detection, and ML NIDS prediction."""
    safe_filename = secure_filename(filename)
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], safe_filename)

    if not os.path.exists(filepath):
        raise FileNotFoundError("PCAP file not found on server.")

    parsed_data = parse_pcap(filepath)
    anomalies = analyze_anomalies(parsed_data)
    ml_prediction = predict_traffic(parsed_data)

    parsed_data['anomalies'] = anomalies
    parsed_data['summary']['anomaly_count'] = len(anomalies)
    parsed_data['ml_prediction'] = ml_prediction

    return parsed_data


@main_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "NetIntel NOC Platform"}), 200


@main_bp.route('/upload', methods=['POST'])
def upload_file():
    """
    Endpoint to upload a PCAP file (.pcap, .cap, .pcapng).
    Validates file extension, magic bytes, and sanitizes filename.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type. Only .pcap, .cap, and .pcapng files are allowed."}), 400

    try:
        file_content = file.read()
        file.seek(0)

        # Magic bytes check for PCAP and PCAPNG
        magic_bytes = file_content[:4]
        valid_magic_bytes = [
            b'\xd4\xc3\xb2\xa1',  # Standard Little-Endian PCAP
            b'\xa1\xb2\xc3\xd4',  # Standard Big-Endian PCAP
            b'\x4d\x3c\xb2\xa1',  # Nanosecond PCAP
            b'\xa1\xb2\x3c\x4d',  # Nanosecond Big-Endian PCAP
            b'\x0a\x0d\x0d\x0a'   # PCAPNG Block
        ]
        if magic_bytes not in valid_magic_bytes:
            return jsonify({"error": "Invalid PCAP file header signature."}), 400

        original_filename = secure_filename(file.filename).lstrip('.\\/')
        if not original_filename:
            original_filename = "capture.pcap"

        unique_id = str(uuid.uuid4())[:8]
        filename = f"{unique_id}_{original_filename}"

        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        retention_hours = current_app.config.get('UPLOAD_RETENTION_HOURS', 24)
        cleanup_old_uploads(current_app.config['UPLOAD_FOLDER'], retention_hours)

        logger.info(f"File uploaded successfully: {filename}")
        return jsonify({
            "message": "File uploaded successfully",
            "filename": filename
        }), 200

    except Exception as e:
        logger.error(f"Error during file upload: {e}")
        return jsonify({"error": f"Failed to upload file: {str(e)}"}), 500


@main_bp.route('/analyze/<filename>', methods=['GET'])
def analyze_file(filename):
    """
    Endpoint to analyze a uploaded PCAP file.
    Returns summary statistics, protocol distribution, top communications,
    topology graph, rule-based anomalies, and parsed packets.
    """
    try:
        logger.info(f"Analyzing file: {filename}")
        data = _get_analysis_data(filename)
        return jsonify(data), 200
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error during analysis: {e}")
        return jsonify({"error": f"An internal error occurred during analysis: {str(e)}"}), 500


@main_bp.route('/export/json/<filename>', methods=['GET'])
def export_json(filename):
    """Export real analysis results as JSON."""
    try:
        data = _get_analysis_data(filename)
        return jsonify(data), 200, {
            'Content-Disposition': f'attachment; filename=NetIntel_Report_{filename}.json'
        }
    except Exception as e:
        logger.error(f"Error exporting JSON: {e}")
        return jsonify({"error": "Failed to export JSON"}), 500


@main_bp.route('/export/csv/<filename>', methods=['GET'])
def export_csv(filename):
    """Export real analysis results as CSV."""
    try:
        data = _get_analysis_data(filename)
        packets = data.get('packets', [])
        
        df = pd.DataFrame(packets)
        csv_data = df.to_csv(index=False)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename=NetIntel_Report_{filename}.csv"}
        )
    except Exception as e:
        logger.error(f"Error exporting CSV: {e}")
        return jsonify({"error": "Failed to export CSV"}), 500


@main_bp.route('/export/pdf/<filename>', methods=['GET'])
def export_pdf(filename):
    """
    Export real analysis results as PDF report containing actual PCAP stats,
    protocol breakdown, top talkers, detected rule anomalies, and packet log.
    """
    try:
        data = _get_analysis_data(filename)
        summary = data['summary']
        proto = data['protocol_distribution']
        comms = data['top_communications']
        anomalies = data['anomalies']
        packets = data['packets']

        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'CustomTitle', parent=styles['Heading1'],
            fontSize=22, textColor=colors.HexColor('#1e40af'),
            spaceAfter=8, fontName='Helvetica-Bold'
        )
        heading_style = ParagraphStyle(
            'CustomHeading', parent=styles['Heading2'],
            fontSize=13, textColor=colors.HexColor('#0f172a'),
            spaceAfter=8, fontName='Helvetica-Bold'
        )

        elements = []

        # Header Title
        elements.append(Paragraph("NetIntel NOC — Traffic Analysis Report", title_style))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 0.15*inch))

        # Summary Section
        elements.append(Paragraph("1. Capture Overview", heading_style))
        summary_table_data = [
            ['Metric', 'Value'],
            ['Filename', summary['filename']],
            ['Total Packets', str(summary['total_packets'])],
            ['Total Traffic Volume', f"{summary['total_bytes']:,} bytes"],
            ['Unique Hosts', str(summary['unique_hosts'])],
            ['Unique Source IPs', str(summary['unique_src_ips'])],
            ['Unique Destination IPs', str(summary['unique_dst_ips'])],
            ['Rule Anomalies Flagged', str(summary['anomaly_count'])]
        ]
        sum_table = Table(summary_table_data, colWidths=[2.5*inch, 3.5*inch])
        sum_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
        ]))
        elements.append(sum_table)
        elements.append(Spacer(1, 0.2*inch))

        # Protocol Breakdown Section
        elements.append(Paragraph("2. Protocol Distribution", heading_style))
        proto_table_data = [
            ['Protocol', 'Packet Count', 'Percentage'],
            ['TCP', str(proto['tcp_count']), f"{proto['tcp_percentage']}%"],
            ['UDP', str(proto['udp_count']), f"{proto['udp_percentage']}%"],
            ['ICMP', str(proto['icmp_count']), f"{proto['icmp_percentage']}%"],
            ['Other', str(proto['other_count']), f"{proto['other_percentage']}%"]
        ]
        proto_table = Table(proto_table_data, colWidths=[2*inch, 2*inch, 2*inch])
        proto_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4f46e5')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
        ]))
        elements.append(proto_table)
        elements.append(Spacer(1, 0.2*inch))

        # Rule Anomalies Section
        if anomalies:
            elements.append(Paragraph("3. Rule-Based Anomaly Detection Results", heading_style))
            anom_table_data = [['ID', 'Reason', 'Source IP', 'Observed Value', 'Severity']]
            for anom in anomalies:
                anom_table_data.append([
                    anom['id'],
                    anom['reason'],
                    anom['src_ip'],
                    anom['observed_value'],
                    anom['severity']
                ])
            anom_table = Table(anom_table_data, colWidths=[0.8*inch, 1.8*inch, 1.2*inch, 1.5*inch, 0.7*inch])
            anom_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef2f2')])
            ]))
            elements.append(anom_table)
            elements.append(Spacer(1, 0.2*inch))

        # Packet Log Sample
        elements.append(PageBreak())
        elements.append(Paragraph("4. Packet Log Sample (First 25 Packets)", heading_style))
        pkt_table_data = [['ID', 'Time', 'Src IP:Port', 'Dst IP:Port', 'Proto', 'Length']]
        for pkt in packets[:25]:
            pkt_table_data.append([
                str(pkt['packet_id']),
                pkt['timestamp'],
                f"{pkt['src_ip']}:{pkt['src_port'] or '*'}",
                f"{pkt['dst_ip']}:{pkt['dst_port'] or '*'}",
                pkt['protocol'],
                f"{pkt['length']}B"
            ])
        pkt_table = Table(pkt_table_data, colWidths=[0.5*inch, 1*inch, 1.8*inch, 1.8*inch, 0.6*inch, 0.7*inch])
        pkt_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0284c7')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f9ff')])
        ]))
        elements.append(pkt_table)

        doc.build(elements)
        pdf_buffer.seek(0)

        return Response(
            pdf_buffer,
            mimetype="application/pdf",
            headers={"Content-disposition": f"attachment; filename=NetIntel_Report_{filename}.pdf"}
        )
    except Exception as e:
        logger.error(f"Error exporting PDF: {e}")
        return jsonify({"error": f"Failed to export PDF: {str(e)}"}), 500

