-- +goose Up
-- +goose StatementBegin
CREATE TABLE teldrive.group_members (
    id SERIAL PRIMARY KEY,
    
    -- Relational Identity
    host_id BIGINT NOT NULL,
    member_id BIGINT NOT NULL UNIQUE, 
    
    -- State Machine
    status VARCHAR(50) NOT NULL CHECK (status IN ('host', 'pending', 'approved')),
    
    -- Host Configuration Data (NULL for Guests)
    stored_hash VARCHAR(64) NULL, 
    channel_id BIGINT NULL,
    
    -- Auditing
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_group_members_host FOREIGN KEY (host_id) REFERENCES teldrive.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_group_members_member FOREIGN KEY (member_id) REFERENCES teldrive.users(user_id) ON DELETE CASCADE
);

-- Constraint 1: Absolute Host Singularity
CREATE UNIQUE INDEX idx_single_host ON teldrive.group_members (status) WHERE (status = 'host');

-- Constraint 2: Fast Lookup for Host's Members
CREATE INDEX idx_group_members_host_status ON teldrive.group_members(host_id, status);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS teldrive.group_members;
-- +goose StatementEnd
