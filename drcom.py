import os
import time
import json
import random
import logging
import configparser
import urllib.parse

import requests


class DrDotComClientError(RuntimeError):
    ERROR_CODES = {
        1001: "获取登录参数失败"
    }

    def __init__(self, errcode):
        self.errcode = errcode

    def __str__(self):
        return f"DrDotComClientError[{self.errcode}]: {self.ERROR_CODES[self.errcode]}"


class DrDotComClient:
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'accept-language': 'zh-CN,zh;q=0.9',
        'Accept-Encoding': "gzip, deflate",
        'Accept-Language': 'zh-CN,zh;q=0.9',  # 以防后患
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'sec-ch-ua': '"Google Chrome";v="87", "\"Not;A\\Brand";v="99", "Chromium";v="87"',
        'sec-ch-ua-mobile': '?0',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1'
    }

    def __init__(self, redirect_url="http://2.2.2.2", conf="user.conf", debug=False):
        self.debug = debug
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s [%(name)s - %(threadName)s]%(message)s')
        logging.getLogger("urllib3").setLevel(logging.INFO)
        self.logger = logging.getLogger("DrDotComClient")
        if self.debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        self.redirect_url = redirect_url
        self.conf_file = conf
        self.jsonp_callback = "dr1002"
        self.user_account = ""
        self.user_password = ""
        self.host = ""
        self.eportal_port = 0
        self.auto_login = False
        self.load_conf()

        # Lived update data
        self.user_status = {}
        self.online = ""
        self.user_ip = ""
        self.user_mac = ""
        self.ac_ip = ""
        self.ac_name = ""
        self.update_user_status()

    def load_conf(self):
        if os.path.exists(self.conf_file):
            cf = configparser.ConfigParser()
            cf.read(self.conf_file, encoding="utf-8")
            self.user_account = cf.get("user", "account")
            self.user_password = cf.get("user", "password")
            self.host = cf.get("config", "host")
            self.eportal_port = cf.get("config", "epHTTPPort")
            self.auto_login = bool(int(cf.get("config", "autoLogin")))
            if int(cf.get("config", "debug")) and not self.debug:
                self.debug = True
                self.logger.setLevel(logging.DEBUG)
            self.logger.info(f"Read config from {self.conf_file}")
        else:
            self.logger.error(f"Config file {self.conf_file} not exists")

    def update_user_status(self):
        # 更新客户端状态
        params = {
            "callback": self.jsonp_callback,
            "jsVersion": "4.1.3",
            "v": random.randint(1000, 9999),
            "lang": "zh"
        }
        res = requests.get(f"http://{self.host}/drcom/chkstatus?", params=params, headers=self.HEADERS)
        self.user_status = json.loads(res.text.split()[0][len(self.jsonp_callback) + 1:-1])
        self.logger.debug(f"Fetch status: {self.user_status}")
        new_status = bool(self.user_status["result"])
        if new_status != self.online:
            self.logger.info(f"Status update: {'Online' if new_status else 'Offline'}")
            self.online = new_status
        if self.online:
            # 在线时更新设备信息
            if self.user_status['v4ip'] != self.user_ip:
                self.logger.info(f"Bind client ip at {self.user_status['v4ip']}")
                self.user_ip = self.user_status['v4ip']
            if self.user_status['olmac'] != self.user_mac:
                self.logger.info(f"Bind client mac at {self.user_status['olmac']}")
                self.user_mac = self.user_status['olmac']

    def get_login_params(self):
        # 未登录时，使用重定向返回参数获得登录设备信息
        res = requests.get(self.redirect_url, headers=self.HEADERS, allow_redirects=False)
        if res.status_code == 302:
            loc = res.headers["Location"]
            query = urllib.parse.parse_qs(loc.split("?")[1])
            # for k, v in query.items():
            #     query[k] = v[0]  # 处理自带list
            self.user_ip = query["wlanuserip"][0]
            self.user_mac = query["wlanusermac"][0]
            self.ac_ip = query["wlanacip"][0]
            self.ac_name = query["wlanacname"][0]
            # return query
        else:
            self.logger.error("Get redirect params failed")
            self.logger.info(f"status_code: {res.status_code}")
            self.logger.debug(res.text)
            raise DrDotComClientError(1001)

    def login(self):
        # 发起登陆
        params = {
            "callback": self.jsonp_callback,
            "jsVersion": "4.1.3",
            "v": random.randint(1000, 9999),
            "lang": "zh",
            "login_method": 1,
            "user_account": self.user_account,
            "user_password": self.user_password,
            "wlan_user_ip": self.user_ip,
            "wlan_user_mac": self.user_mac,
            "wlan_ac_ip": self.ac_ip,
            "wlan_ac_name": self.ac_name,
            "terminal_type": 1
        }
        self.logger.info(f"Start login to {self.user_account}")
        res = requests.get(f"http://{self.host}:{self.eportal_port}/eportal/portal/login?", params=params,
                           headers=self.HEADERS)
        result = json.loads(res.text.split()[0][len(self.jsonp_callback) + 1:-1])
        if result["result"]:
            self.logger.info("Login success")
            self.update_user_status()
        else:
            self.logger.error(f"Login failed[{result['ret_code']}]: {result['msg']}")


if __name__ == '__main__':
    o = DrDotComClient()
