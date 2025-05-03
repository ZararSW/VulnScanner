import os
import logging
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

port = int(os.environ.get("PORT", 5000))
app.run(host="0.0.0.0", port=port)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "vulnerability_scanner_default_key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # needed for url_for to generate with https

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///scanner.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

with app.app_context():
    # Import models after db initialization to avoid circular imports
    import models  # noqa: F401
    from scanner.scanner import Scanner
    db.create_all()

@app.route('/')
def index():
    """Dashboard showing recent scans and system status"""
    from models import Scan
    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    return render_template('dashboard.html', scans=recent_scans)

@app.route('/scan', methods=['GET', 'POST'])


def scan():
    """Initiate a new scan"""
    from models import Scan, Target
    
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        scan_name = request.form.get('scan_name', f"Scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
        scan_depth = request.form.get('scan_depth', 'medium')
        
        if not target_url:
            flash('Target URL is required', 'danger')
            return redirect(url_for('index'))
            
        # Create new scan
        target = Target(url=target_url)
        db.session.add(target)
        db.session.flush()
        
        new_scan = Scan(
            name=scan_name,
            target_id=target.id,
            status='queued',
            scan_depth=scan_depth
        )
        db.session.add(new_scan)
        db.session.commit()
        
        # In a production system, we'd use a task queue like Celery
        # For simplicity, we'll run the scan synchronously
        scanner = Scanner(target_url, scan_id=new_scan.id, depth=scan_depth)
        scanner.start_scan_async()
        
        flash('Scan initiated successfully', 'success')
        return redirect(url_for('scan_results', scan_id=new_scan.id))
        
    return render_template('dashboard.html')

@app.route('/results/<int:scan_id>')
def scan_results(scan_id):
    """View results of a specific scan"""
    from models import Scan, Vulnerability
    
    scan = Scan.query.get_or_404(scan_id)
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
    
    return render_template('scan_results.html', scan=scan, vulnerabilities=vulnerabilities)

@app.route('/vulnerability/<int:vuln_id>')
def vulnerability_detail(vuln_id):
    """View detailed information about a vulnerability"""
    from models import Vulnerability
    
    vulnerability = Vulnerability.query.get_or_404(vuln_id)
    
    return render_template('vulnerability_detail.html', vulnerability=vulnerability)

@app.route('/api/scan_status/<int:scan_id>')
def scan_status(scan_id):
    """API endpoint to check scan status"""
    from models import Scan
    
    scan = Scan.query.get_or_404(scan_id)
    
    return jsonify({
        'id': scan.id,
        'status': scan.status,
        'progress': scan.progress,
        'vulnerabilities_found': scan.vulnerabilities_count
    })

@app.route('/api/scan_vulnerabilities/<int:scan_id>')
def scan_vulnerabilities(scan_id):
    """API endpoint to get real-time vulnerabilities"""
    from models import Scan, Vulnerability
    import json
    
    # Get latest vulnerabilities
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).order_by(Vulnerability.id.desc()).all()
    
    # Format for JSON response
    vulnerability_list = []
    for vuln in vulnerabilities:
        try:
            evidence = json.loads(vuln._evidence) if vuln._evidence else {}
        except:
            evidence = {}
            
        vulnerability_list.append({
            'id': vuln.id,
            'title': vuln.title,
            'type': vuln.vulnerability_type,
            'severity': vuln.severity,
            'affected_url': vuln.affected_url,
            'is_verified': vuln.is_verified,
            'is_false_positive': vuln.is_false_positive,
            'proof_of_concept': vuln.proof_of_concept,
            'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None,
            'evidence': evidence
        })
    
    # Get scan info
    scan = Scan.query.get_or_404(scan_id)
    
    return jsonify({
        'scan_id': scan_id,
        'scan_status': scan.status,
        'scan_progress': scan.progress,
        'vulnerabilities': vulnerability_list
    })

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return render_template('500.html'), 500
