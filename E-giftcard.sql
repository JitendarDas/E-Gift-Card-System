CREATE DATABASE mydatabase;
USE mydatabase;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    password VARCHAR(60),
    balance INT DEFAULT 0
);

CREATE TABLE gift_cards (
    card_name VARCHAR(100),
    card_id INT PRIMARY KEY AUTO_INCREMENT,
    card_value INT,
    issue_date DATE,
    expiry_date DATE,
    merchant_id INT,
    available BOOLEAN,
    customer_id INT,
    FOREIGN KEY (merchant_id) REFERENCES merchant(id),
    FOREIGN KEY (customer_id) REFERENCES users(id)
);

CREATE TABLE transaction (
    transaction_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    card_id INT,
    transaction_date DATE NOT NULL,
    transaction_type VARCHAR(50) NOT NULL,
    transaction_amount DECIMAL(10, 2) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (card_id) REFERENCES gift_cards(card_id)
);

CREATE TABLE merchant (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100),
    email VARCHAR(100),
    password VARCHAR(60),
    balance Int
);

CREATE TABLE gift_card_requests (
    request_id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT,
    card_name VARCHAR(100),
    card_value INT,
    card_id INT,
    quantity INT,
    request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('Pending', 'Approved', 'Denied') DEFAULT 'Pending',
    FOREIGN KEY (customer_id) REFERENCES users(id),
    FOREIGN KEY (card_id) REFERENCES gift_cards(card_id)
);

CREATE TABLE admin (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    password VARCHAR(60)
);