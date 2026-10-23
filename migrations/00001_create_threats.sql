-- +goose Up
CREATE TABLE threats (
    md5 TEXT PRIMARY KEY CHECK (md5 ~ '^[a-f0-9]{32}$'),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255 AND btrim(name) <> ''),
    type TEXT NOT NULL CHECK (type IN ('trojan', 'virus', 'worm', 'ransomware', 'spyware', 'adware', 'rootkit', 'other')),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 4096),
    tags TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(tags) <= 20),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now() CHECK (updated_at >= created_at)
);

-- +goose Down
DROP TABLE threats;
