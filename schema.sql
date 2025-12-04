CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(100) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  code VARCHAR(100),
  unit VARCHAR(50),
  cost_raw NUMERIC(12,2) DEFAULT 0,
  cost_packaging NUMERIC(12,2) DEFAULT 0,
  cost_labor NUMERIC(12,2) DEFAULT 0,
  cost_logistics_base NUMERIC(12,2) DEFAULT 0,
  cost_tax_base NUMERIC(12,2) DEFAULT 0,
  cost_other NUMERIC(12,2) DEFAULT 0
);

CREATE TABLE IF NOT EXISTS locations (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  state VARCHAR(10),
  city VARCHAR(100),
  freight NUMERIC(12,2) DEFAULT 0,
  extra_tax_percent NUMERIC(5,2) DEFAULT 0,
  other_adjust_percent NUMERIC(5,2) DEFAULT 0
);
