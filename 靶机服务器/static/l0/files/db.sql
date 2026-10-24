-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
-- Host: 10.31.7.15    Database: qu_zwfw
-- 某某区政务服务中心  导出时间 2024-02-28
-- ------------------------------------------------------

DROP TABLE IF EXISTS `qu_staff`;
CREATE TABLE `qu_staff` (
  `id_card` varchar(18) NOT NULL,
  `name` varchar(32) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `dept` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id_card`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `qu_staff` (`id_card`, `name`, `phone`, `dept`) VALUES
  ('330106199003074512', '张伟明', '13857198264', '信息中心'),
  ('330106198711231267', '李  娜', '15968820031', '政务公开科'),
  ('330103199512086631', '王建国', '13777890126', '综合处'),
  ('330104198205123049', '陈晓东', '18605711688', '运维保障组'),
  ('330102199408162238', '刘丹青', '13588220099', '审批服务科');

-- Dump completed on 2024-02-28 11:07:33
