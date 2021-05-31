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
        1000: "尝试请求失败，请检查无线连接",
        1001: "获取登录参数失败"
    }

    def __init__(self, errcode: int):
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

    def __init__(self, redirect_url: str = "http://2.2.2.2", conf: str = "user.conf", debug: bool = False):
        self.debug = debug
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s %(levelname)s [%(name)s - %(threadName)s]%(message)s')
        # logging.getLogger("urllib3").setLevel(logging.INFO)  # Disable urllib3 debug output
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
        """从配置文件读取配置"""
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

    def __drcom_api_request_wrapper(self, url: str, params: dict = None) -> requests.Response:
        """服务端调用API请求包装器，包含错误封装"""
        err_flag = False
        try:
            return requests.get(url, params=params, headers=self.HEADERS, allow_redirects=False)
        except requests.exceptions.ConnectionError as err:
            self.logger.error(err)
            err_flag = 1000
        finally:
            if err_flag:
                raise DrDotComClientError(err_flag)

    def __on_user_status(self, status_data: dict):
        """控制用户动态信息的更新与展示"""
        for k, v in status_data.items():
            if k == "online" and v != self.online:
                self.online = v
                self.logger.info(f"Status update: {'Online' if self.online else 'Offline'}")
            elif k == "user_ip" and v != self.user_ip:
                self.user_ip = v
                self.logger.info(f"Bind client ip at {self.user_ip}")
            elif k == "user_mac" and v != self.user_mac:
                self.user_mac = v
                self.logger.info(f"Bind client mac at {self.user_mac}")
            elif k == "ac_ip" and v != self.ac_ip:
                self.ac_ip = v
                self.logger.info(f"Updated ac ip at {self.ac_ip}")
            elif k == "ac_name" and v != self.ac_name:
                self.ac_name = v
                self.logger.info(f"Updated ac name at {self.ac_name}")

    def reload(self):
        """手动重载配置文件，适用于配置热重载"""
        self.load_conf()

    def update_user_status(self):
        """更新客户端状态"""
        params = {
            "callback": self.jsonp_callback,
            "jsVersion": "4.1.3",
            "v": random.randint(1000, 9999),
            "lang": "zh"
        }

        res = self.__drcom_api_request_wrapper(f"http://{self.host}/drcom/chkstatus?", params)
        self.user_status = json.loads(res.text.strip().rstrip(";")[len(self.jsonp_callback) + 1:-1])
        self.logger.debug(f"Fetch status: {self.user_status}")
        new_status = bool(self.user_status["result"])
        # 在线与离线状态更新数据不同
        if new_status:
            self.__on_user_status({
                "online": new_status,
                "user_ip": self.user_status['v4ip'],
                "user_mac": self.user_status['olmac']
            })
        else:
            self.__on_user_status({
                "online": new_status
            })
            self.get_login_params()  # 未登录时使用重定向链接获得更多信息

    def get_login_params(self):
        """未登录时，使用重定向返回参数获得登录设备信息"""
        res = self.__drcom_api_request_wrapper(self.redirect_url)
        if res.status_code == 302:
            loc = res.headers["Location"]
            query = urllib.parse.parse_qs(loc.split("?")[1])
            # for k, v in query.items():
            #     query[k] = v[0]  # 处理自带list
            self.__on_user_status({
                "user_ip": query["wlanuserip"][0],
                "user_mac": query["wlanusermac"][0],
                "ac_ip": query["wlanacip"][0],
                "ac_name": query["wlanacname"][0]
            })
            # return query
        else:
            self.logger.error("Get redirect params failed")
            self.logger.info(f"status_code: {res.status_code}")
            self.logger.debug(res.text)
            raise DrDotComClientError(1001)

    def login(self, force=False):
        """发起登陆"""
        self.get_login_params()  # 强制更新
        if self.online:
            self.logger.warning("Client is already online!")
            if not force:
                return
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
        res = self.__drcom_api_request_wrapper(f"http://{self.host}:{self.eportal_port}/eportal/portal/login?", params)
        result = json.loads(res.text.strip().rstrip(";")[len(self.jsonp_callback) + 1:-1])
        if result["result"]:
            self.logger.info("Login success")
            self.update_user_status()
        else:
            self.logger.error(f"Login failed[{result['ret_code']}]: {result['msg']}")

    def show_status(self):
        """展示用户信息"""
        self.update_user_status()
        print(f"==========Client status: {'Online' if self.online else 'Offline'}==========")
        print(
            f"user(account/ip/mac/nid/gid): {self.user_account} || {self.user_ip} || {self.user_mac} || {self.user_status.get('NID')} || {self.user_status.get('gid')}")
        if self.online:
            if self.user_status["stime"]:
                print(f"time(start/end): {self.user_status['stime']} || {self.user_status['etime']}")
            min_time = f"{int(self.user_status['time'] / 60)}:{self.user_status['time'] % 60}"
            act_time = f"{int(self.user_status['actt'] / 3600)}:{int(self.user_status['actt'] % 3600 / 60)}:{self.user_status['actt'] % 3600 % 60}"
            print(f"time(min_count/act): {min_time} || {act_time}")
            print(f"frame(down/up): {self.user_status['actdf']} || {self.user_status['actuf']}")

    def logout(self):
        """登出客户端"""
        self.logger.info("Client logout")
        params = {
            "callback": self.jsonp_callback
        }
        res = self.__drcom_api_request_wrapper(f"http://{self.host}:{self.eportal_port}/eportal/portal/logout?", params)
        self.update_user_status()


if __name__ == '__main__':
    d = DrDotComClient(debug=False)
    d.show_status()
