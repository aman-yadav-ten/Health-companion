CREATE TABLE `project`.`accounts` (
id int(11) NOT NULL AUTO_INCREMENT,
full_name varchar(120) NOT NULL,
date_of_birth date NOT NULL,
username varchar(50) NOT NULL, 
password_hash varchar(255) NOT NULL,
PRIMARY KEY (id)
);
