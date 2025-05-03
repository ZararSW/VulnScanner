import json
from datetime import datetime
from app import db
from sqlalchemy.ext.hybrid import hybrid_property

class Target(db.Model):
    __tablename__ = 'targets'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(1024), nullable=False)
    ip_address = db.Column(db.String(45))
    hostname = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_scanned = db.Column(db.DateTime)
    
    # Relationships
    scans = db.relationship('Scan', backref='target', lazy=True)
    subdomains = db.relationship('Subdomain', backref='target', lazy=True)

    def __repr__(self):
        return f'<Target {self.url}>'

class Subdomain(db.Model):
    __tablename__ = 'subdomains'

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45))
    is_active = db.Column(db.Boolean, default=True)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Subdomain {self.name}>'

class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=False)
    status = db.Column(db.String(50), default='queued')  # queued, in_progress, completed, failed
    progress = db.Column(db.Integer, default=0)  # 0-100 percent
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scan_depth = db.Column(db.String(50), default='medium')  # low, medium, high
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)
    reconnaissance_data = db.relationship('ReconnaissanceData', backref='scan', lazy=True)
    
    @hybrid_property
    def duration(self):
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    @hybrid_property
    def vulnerabilities_count(self):
        return len(self.vulnerabilities)
    
    def __repr__(self):
        return f'<Scan {self.id}: {self.name}>'

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    vulnerability_type = db.Column(db.String(100), nullable=False)  # XSS, SQLi, etc.
    severity = db.Column(db.String(50), nullable=False)  # low, medium, high, critical
    cvss_score = db.Column(db.Float)
    affected_url = db.Column(db.String(1024), nullable=False)
    proof_of_concept = db.Column(db.Text)  # Steps to reproduce or exploit code
    is_verified = db.Column(db.Boolean, default=False)
    is_false_positive = db.Column(db.Boolean, default=False)
    _evidence = db.Column('evidence', db.Text)  # Serialized JSON
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    validation_steps = db.Column(db.Text)
    
    @property
    def evidence(self):
        if self._evidence:
            return json.loads(self._evidence)
        return {}
    
    @evidence.setter
    def evidence(self, value):
        self._evidence = json.dumps(value)
    
    def __repr__(self):
        return f'<Vulnerability {self.id}: {self.title}>'

class ReconnaissanceData(db.Model):
    __tablename__ = 'reconnaissance_data'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    data_type = db.Column(db.String(100), nullable=False)  # endpoint, technology, open_port, etc.
    data_value = db.Column(db.Text, nullable=False)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ReconData {self.id}: {self.data_type}>'
