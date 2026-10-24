-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
--
-- Host: 10.12.34.51    Database: zwfw_prod
-- ------------------------------------------------------
-- Server version	5.7.29-log

/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET TIME_ZONE='+08:00' */;

--
-- 表的结构 `zwfw_staff`
--

DROP TABLE IF EXISTS `zwfw_staff`;
CREATE TABLE `zwfw_staff` (
  `id_card` varchar(18) NOT NULL,
  `name` varchar(32) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `dept` varchar(64) DEFAULT NULL,
  `staff_no` varchar(16) DEFAULT NULL,
  PRIMARY KEY (`id_card`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- 转存表中的数据 `zwfw_staff`
--

INSERT INTO `zwfw_staff` (`id_card`, `name`, `phone`, `dept`, `staff_no`) VALUES
  ('330106199003074512', '张伟明', '13857198264', '信息中心', 'GW100237'),
  ('330106198711231267', '李  娜', '15968820031', '政务公开科', 'GW100581'),
  ('330103199512086631', '王建国', '13777890126', '综合处', 'GW100842'),
  ('330104198205123049', '陈晓东', '18605711688', '运维保障组', 'GW100963'),
  ('330102199408162238', '刘丹青', '13588220099', '审批服务科', 'GW101127'),
  ('330105197903251156', '赵洪涛', '13906513388', '数据资源科', 'GW101204'),
  ('330103199109084427', '孙丽华', '15868122990', '信息中心', 'GW101355'),
  ('330108199602113315', '周文斌', '13736008866', '网络安全岗', 'GW101418');

DROP TABLE IF EXISTS `zwfw_account`;
CREATE TABLE `zwfw_account` (
  `username` varchar(32) NOT NULL,
  `password` varchar(64) DEFAULT NULL,
  `role` varchar(16) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `zwfw_account` (`username`, `password`, `role`) VALUES
  ('admin', 'Admin@888', 'admin'),
  ('zhangweiming', 'Zwfw@2024', 'editor'),
  ('liyang', 'Zwfw@2024', 'viewer');

-- Dump completed on 2024-03-11 17:42:08
