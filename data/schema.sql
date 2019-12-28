CREATE DATABASE audit;

USE audit;

CREATE TABLE IF NOT EXISTS `namespace.audit.audit` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userId` varchar(45) NOT NULL,
  `userType` int(11) NOT NULL,
  `event` varchar(45) NOT NULL,
  `resource` varchar(45) DEFAULT NULL,
  `userAgent` text NOT NULL,
  `ip` varchar(45) NOT NULL,
  `location` varchar(45) DEFAULT NULL,
  `time` datetime NOT NULL,
  `data` longtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `index_1` (`userId`,`userType`),
  KEY `index_2` (`event`),
  KEY `index_3` (`resource`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;