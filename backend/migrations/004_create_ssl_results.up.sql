-- Migration: Create ssl_scan_results table
-- Version: 004
-- Description: Stores SSL/TLS certificate scan results

CREATE TABLE IF NOT EXISTS ssl_scan_results (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL,
    scan_job_id UUID NOT NULL,
    domain VARCHAR(255) NOT NULL,
    
    -- Certificate Info (stored as JSON for flexibility, or flattened)
    -- Flattened for easier querying of specific fields
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    valid_from TIMESTAMP NOT NULL,
    valid_until TIMESTAMP NOT NULL,
    days_until_expiry INTEGER NOT NULL,
    is_expired BOOLEAN NOT NULL,
    is_self_signed BOOLEAN NOT NULL,
    san TEXT NOT NULL, -- JSON array of strings
    
    -- Connection Info
    tls_version VARCHAR(20) NOT NULL,
    cipher_suite VARCHAR(100) NOT NULL,
    key_exchange VARCHAR(50) NOT NULL,
    
    -- Analysis
    grade VARCHAR(5) NOT NULL,
    issues TEXT NOT NULL, -- JSON array of strings
    
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Foreign keys
    CONSTRAINT fk_ssl_result_asset 
        FOREIGN KEY (asset_id) 
        REFERENCES assets(id) 
        ON DELETE CASCADE,
    CONSTRAINT fk_ssl_result_scan_job 
        FOREIGN KEY (scan_job_id) 
        REFERENCES scan_jobs(id) 
        ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_ssl_results_asset_id ON ssl_scan_results(asset_id);
CREATE INDEX idx_ssl_results_scan_job_id ON ssl_scan_results(scan_job_id);
CREATE INDEX idx_ssl_results_grade ON ssl_scan_results(grade);
CREATE INDEX idx_ssl_results_valid_until ON ssl_scan_results(valid_until);
