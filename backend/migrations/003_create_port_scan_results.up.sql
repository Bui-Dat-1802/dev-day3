-- Migration: Create port_scan_results table
-- Version: 004
-- Description: Stores port scan results used by ScanService (open_ports JSONB, counts, durations)

CREATE TABLE IF NOT EXISTS port_scan_results (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL,
    scan_job_id UUID NOT NULL,
    ip_address INET NOT NULL,
    open_ports JSONB NOT NULL,
    closed_ports INTEGER,
    total_scanned INTEGER,
    scan_duration_ms INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_port_scan_result_asset
        FOREIGN KEY (asset_id)
        REFERENCES assets(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_port_scan_result_scan_job
        FOREIGN KEY (scan_job_id)
        REFERENCES scan_jobs(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_port_scan_results_asset_id ON port_scan_results(asset_id);
CREATE INDEX IF NOT EXISTS idx_port_scan_results_scan_job_id ON port_scan_results(scan_job_id);
