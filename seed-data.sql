-- seed-data.sql — schema + populated demo data for EduPortal.
-- Matches the project README. Loaded automatically by docker-compose on first run,
-- or manually:  mysql -u root -p eduportal < seed-data.sql

CREATE DATABASE IF NOT EXISTS eduportal CHARACTER SET utf8mb4;
USE eduportal;

DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS courses;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id        INT AUTO_INCREMENT PRIMARY KEY,
  username  VARCHAR(50)  NOT NULL UNIQUE,
  password  VARCHAR(100) NOT NULL,          -- plaintext in VULN demo; hashed note in README
  email     VARCHAR(120) NOT NULL,
  bio       TEXT,                            -- stored-XSS sink (rendered on profile)
  role      VARCHAR(20)  NOT NULL DEFAULT 'student'
);

CREATE TABLE courses (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(120) NOT NULL,
  description TEXT
);

CREATE TABLE comments (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  author   VARCHAR(50) NOT NULL,
  body     TEXT NOT NULL,                    -- stored-XSS sink (rendered on board)
  created  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- The "secret" the SQL-injection advanced chain is meant to extract.
INSERT INTO users (username, password, email, bio, role) VALUES
  ('admin',  'S3cr3t_Admin!2026', 'admin@eduportal.test',  'Site administrator.',        'admin'),
  ('alice',  'alice123',          'alice@eduportal.test',  'CS student, loves crypto.',  'student'),
  ('bob',    'bobpass',           'bob@eduportal.test',    'Enrolled in Networks 101.',  'student'),
  ('carol',  'carol2024',         'carol@eduportal.test',  'Exchange student.',          'student');

INSERT INTO courses (name, description) VALUES
  ('Information Security',     'Threats, cryptography, web security and defence.'),
  ('Networks 101',             'TCP/IP, routing, switching and the OSI model.'),
  ('Databases',                'Relational modelling, SQL and transactions.'),
  ('Operating Systems',        'Processes, memory, scheduling and the stack.'),
  ('Web Development',          'Full-stack apps, HTTP and REST APIs.');

INSERT INTO comments (author, body) VALUES
  ('alice', 'Great lecture on buffer overflows today!'),
  ('bob',   'Can someone share the Networks notes?'),
  ('carol', 'The databases assignment deadline please?');

-- Low-privilege application user (defence-in-depth; used in SAFE mode discussion).
-- In VULN mode the app may connect as a broader user to make information_schema
-- enumeration visible. Keep this grant limited in a real deployment.
-- CREATE USER IF NOT EXISTS 'eduportal'@'%' IDENTIFIED BY 'eduportal_pw';
-- GRANT SELECT, INSERT, UPDATE ON eduportal.* TO 'eduportal'@'%';
