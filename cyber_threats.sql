--@block
CREATE TABLE users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100),
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,  -- Hashed password
    role ENUM('Admin', 'Analyst', 'Viewer') NOT NULL,
    organization VARCHAR(100)
);

--@block
CREATE TABLE threats (
    threat_id INT PRIMARY KEY AUTO_INCREMENT,
    threat_type VARCHAR(50),
    description TEXT,
    severity ENUM('Low', 'Medium', 'High', 'Critical'),
    source VARCHAR(100),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reported_by INT,
    FOREIGN KEY (reported_by) REFERENCES users(user_id) ON DELETE SET NULL
);

--@block
CREATE TABLE attack_logs (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    threat_id INT,
    attacker_ip VARCHAR(100),
    target_ip VARCHAR(100),
    attack_type VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (threat_id) REFERENCES threats(threat_id) ON DELETE CASCADE
);

--@block
CREATE TABLE reports (
    report_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    report_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    summary TEXT,
    threat_count INT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

--@block
CREATE TABLE threat_feeds (
    feed_id INT PRIMARY KEY AUTO_INCREMENT,
    source_name VARCHAR(100),
    source_url VARCHAR(255),
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


--@block
SELECT * FROM users;

--@block
SELECT * FROM threats;