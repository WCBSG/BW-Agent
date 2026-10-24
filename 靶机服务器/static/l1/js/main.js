/* main.js - 站点交互脚本 */
(function () {
  document.addEventListener('DOMContentLoaded', function () {
    var links = document.querySelectorAll('nav a');
    for (var i = 0; i < links.length; i++) {
      links[i].addEventListener('click', function () {
        /* 埋点：记录导航点击 */
      });
    }
  });
})();
