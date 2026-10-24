部署说明
========================================
1. 解压站点包到 /var/www/zwfw
2. 导入数据库： mysql -u root -p zwfw_prod < db.sql
3. 复制 config.php.bak 为 config.php 并修改数据库口令
4. 后台入口 /admin/ ，默认账号见 config.php.bak
5. 内网 OA 地址： http://10.12.34.51:8080/

运维组  2024-03-11
