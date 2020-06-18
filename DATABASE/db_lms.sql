-- phpMyAdmin SQL Dump
-- version 4.7.4
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jun 02, 2018 at 04:48 PM
-- Server version: 10.1.28-MariaDB
-- PHP Version: 7.1.10

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";




/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `lms`
--

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

create table `uedu_tutor`(
  `idx` INT PRIMARY KEY AUTO_INCREMENT,
  `id` varchar(70),
  `pw` varchar(100),
  `mega_name` varchar(20),
  `position` varchar(20),
  `first_name` varchar(20),
  `last_name` varchar(20),
  `sex`  varchar(20),
  `date_of_birth` varchar(200),
  `address` varchar(200),
  `major` varchar(200),
  `school` varchar(200),
  `workexp` JSON,
  `introduction` varchar(200),
  `mobile_number` varchar(200),
  `email` varchar(200),
  `specialty` varchar(200),
  `am` boolean not null default 0,
  `pm` boolean not null default 0,
  `workplace` varchar(200),
  `start_am` varchar(200),
  `end_am` varchar(200),
  `start_pm` varchar(200),
  `end_pm` varchar(200),
  `affiliation` varchar(200),
  `language` varchar(200),
  `country` varchar(200),
  `team` varchar(200),
  `team_monitoring` varchar(200),
  `starting_date` varchar(200),
  `class_type` json,
  `academies` json,
  `recording_path` varchar(200),
  `class_schedule` json,
  `status` varchar(20) DEFAULT 'active',
  `conn_id` varchar(32) ,


  updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW(),
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP

)
 ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `users`
--











create table leveltest(
idx INT PRIMARY KEY AUTO_INCREMENT,
name varchar(20),
kr_name varchar(20),
phone_number varchar(200),
academy varchar(200),
class_type varchar(200),
date datetime DEFAULT CURRENT_TIMESTAMP,
hour int,
minute int,
duration int,
class_start datetime,
class_end datetime,
category varchar(20) DEFAULT 'leveltest',
applicable_days json,
classid varchar(32),
preference_number varchar(32),
can_take_over boolean not null default 1,
skypeid varchar(200),
conn_id varchar(32),
position varchar(32) NOT NULL DEFAULT 'Student',
updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW(),
created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB DEFAULT CHARSET=latin1;


create table evaluation(
idx INT PRIMARY KEY AUTO_INCREMENT,
studentname varchar(200) DEFAULT NULL,
evaluation json,
phone_number varchar(200),
type varchar(30),
classid varchar(32),
preference_number varchar(32),

updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW(),
created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB DEFAULT CHARSET=latin1;

create table correction(
idx INT PRIMARY KEY AUTO_INCREMENT,
studentname varchar(200) DEFAULT NULL,
student_idx int(11),
correction json,
classid varchar(32),


updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW(),
created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB DEFAULT CHARSET=latin1;

create table qa(
idx INT PRIMARY KEY AUTO_INCREMENT,
studentname varchar(200) DEFAULT NULL,
student_idx int(11),
qa json,
classid varchar(32),


updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW(),
created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB DEFAULT CHARSET=latin1;


create table faq(

  idx INT PRIMARY KEY AUTO_INCREMENT,
  question text(1000),
  answer text(1000),
  faqid varchar(32),
  op_idx int(11),
  op_name varchar(200),



  updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW(),
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )ENGINE=InnoDB DEFAULT CHARSET=latin1;


  create table academy(

    idx INT PRIMARY KEY AUTO_INCREMENT,
    name varchar(200),
    website varchar(200),
    description text(1000),
    special_instruction text(1000),
    cs_number varchar(200),
    calling_prefix varchar(200),
    academyid varchar(32),

    updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW(),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )ENGINE=InnoDB DEFAULT CHARSET=latin1;

  create table message(

    idx INT PRIMARY KEY AUTO_INCREMENT,
    sender_conn_id varchar(32),
    receiver_conn_id varchar(32),
    messages json,
    chat_id varchar(32),
    updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW(),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )ENGINE=InnoDB DEFAULT CHARSET=latin1;


create table announcement(
idx INT PRIMARY KEY AUTO_INCREMENT,
announcer varchar(200),
announcer_idx varchar(200),
subject text(1000),
content text(1000),
category varchar(200),
announcement_id varchar(32),


updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW(),
created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB DEFAULT CHARSET=latin1;





create table regularclass(
idx INT PRIMARY KEY AUTO_INCREMENT,
id varchar(70),
pw varchar(100),
name varchar(20),
kr_name varchar(20),
phone_number varchar(200),
academy varchar(200),
level varchar(200),
class_type varchar(200),
days int,
date datetime,
can_take_over  boolean not null default 0,
applicable_days json,
hour int,
minute int,
duration int,
period int,
price int,
curriculum varchar(100),
bookMaterial varchar(100),
email varchar(100),

skypeid varchar(200),


class_start datetime,
class_end datetime,

category varchar(20) DEFAULT 'regularclass',
recordings boolean not null default 0,
takeover boolean not null default 0,
classid varchar(32),
preference_number varchar(32),
conn_id varchar(32) ,
position varchar(32) NOT NULL DEFAULT 'Student',
updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW(),
created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=InnoDB DEFAULT CHARSET=latin1;






--
-- Indexes for dumped tables
--

--
-- Indexes for table `users`
--


--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `users`
--

COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
