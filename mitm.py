#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari

import os
import re
import time
import json
import asyncio
import traceback
import threading
import urllib.parse
import mitmproxy.http
from multiprocessing import Process, Queue
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import ctx, http
import jinja2
import aiohttp_jinja2
from aiohttp import web
from config import getConfig
from logger import logger
import sqlExecuter


q = Queue()


class SERVER(object):
    def __init__(self, q):
        self.q = q

    @staticmethod
    async def home(request):
        return aiohttp_jinja2.render_template('home.html', request, context={'datas': sqlExecuter.home(request),
                                                                             'context': getConfig('context')})

    @staticmethod
    async def course(request):
        return aiohttp_jinja2.render_template('course.html', request, context={'context':getConfig("context")})

    @staticmethod
    async def isRun(request):
        try:
            data = json.loads(await request.text())
            sqlExecuter.isRun(data)
            return web.json_response({'code': 1, 'msg': 'successful', 'data': None})
        except Exception as err:
            return web.json_response({'code': 0, 'msg': str(err), 'data': None})

    @staticmethod
    async def delete(request):
        try:
            ID = request.match_info['Id']
            sqlExecuter.delete(ID)
            return web.json_response({'code': 1, 'msg': 'successful', 'data': None})
        except Exception as err:
            return web.json_response({'code': 0, 'msg': str(err), 'data': None})

    @staticmethod
    async def edit(request):
        try:
            ID = request.match_info['Id']
            data = sqlExecuter.edit(ID)
            return web.json_response({'code': 1, 'msg': 'successful', 'data': data})
        except Exception as err:
            return web.json_response({'code': 0, 'msg': str(err), 'data': None})

    @staticmethod
    async def update(request):
        try:
            data = json.loads(await request.text())
            if data.get('method') != '0':
                if not isinstance(json.loads(data.get('fields')), dict):
                    raise Exception('篡改字段的值不是合法的Json')
            sqlExecuter.update(data)
            return web.json_response({'code': 1, 'msg': 'successful', 'data': None})
        except json.JSONDecodeError:
            return web.json_response({'code': 0, 'msg': '篡改字段的值不是合法的Json', 'data': None})
        except Exception as err:
            logger.error(traceback.format_exc())
            return web.json_response({'code': 0, 'msg': str(err), 'data': None})

    @staticmethod
    async def save(request):
        try:
            data = json.loads(await request.text())
            if data.get('method') != '0':
                if not isinstance(json.loads(data.get('fields')), dict):
                    raise Exception('篡改字段的值不是合法的Json')
            sqlExecuter.save(data)
            return web.json_response({'code': 1, 'msg': 'successful', 'data': None})
        except json.JSONDecodeError:
            return web.json_response({'code': 0, 'msg': '篡改字段的值不是合法的Json', 'data': None})
        except Exception as err:
            return web.json_response({'code': 0, 'msg': str(err), 'data': None})

    async def reload(self, request):
        try:
            self.q.put(sqlExecuter.reload())
            return web.json_response({'code': 1, 'msg': 'successful', 'data': None})
        except Exception as err:
            return web.json_response({'code': 0, 'msg': str(err), 'data': None})


class RequestEvent(object):
    def __init__(self, q):
        self._data = []
        self.q = q

        thread_01 = threading.Thread(target=self.get_queue)
        thread_01.daemon = True
        thread_01.start()

    def get_queue(self):
        while True:
            self._data = self.q.get()
            time.sleep(1)

    def http_connect(self, flow: mitmproxy.http.HTTPFlow):
        pass

    def request(self, flow: mitmproxy.http.HTTPFlow):
        request_dict = {'url': '', 'method': '', 'scheme': '', 'hostname': '', 'port': 80, 'path': '',
                        'query': '', 'data': '', 'fragment': '', 'origin_data': ''}

        url_parse = urllib.parse.urlparse(flow.request.url)      # 解析url
        request_dict['url'] = flow.request.url
        request_dict['method'] = flow.request.method  # 请求方式
        request_dict['scheme'] = url_parse.scheme   # 协议
        request_dict['hostname'] = url_parse.hostname   # 域名
        request_dict['port'] = flow.request.port    # 端口
        request_dict['path'] = url_parse.path  # 请求路径

        logger.info(f'{request_dict["scheme"]} - {request_dict["method"]} - {request_dict["hostname"]}:'
                    f'{request_dict["port"]} - {request_dict["path"]}')

        result = self.intercept(request_dict)
        if result['flag']:  # http请求命令拦截规则
            if result['rule_data'][8] == 0: # 直接拦截
                request_dict['query'] = self.decode_query(urllib.parse.unquote(url_parse.query))  # URL中的请求参数
                request_dict['fragment'] = url_parse.fragment
                data = flow.request.get_text()
                request_dict['data'] = self.decode_data(data) if data else data  # post请求的参数
                logger.debug(f"URL中的请求参数处理后的数据为：{request_dict['query']}")
                logger.debug(f"POST请求体中的参数处理后的数据为：{request_dict['data']}")

                data = self.return_response(result['rule_data'], request_dict)
                flow.response = http.Response.make(status_code=data['status_code'], content=data['content'])
                logger.info(f"{request_dict['url']} 已被直接拦截")

            if result['rule_data'][8] == 1:  # 修改请求参数
                request_dict['origin_data'] = flow.request.get_text()
                url, data = self.falsify_request(result['rule_data'][5], request_dict)
                flow.request.url = url
                flow.request.text = data
                logger.info(f"{request_dict['url']} 请求参数已篡改完成")

    def response(self, flow: mitmproxy.http.HTTPFlow):
        response_dict = {'url': '', 'hostname': '', 'path': '', 'data': ''}
        url_parse = urllib.parse.urlparse(flow.request.url)  # 解析url
        response_dict['url'] = flow.request.url
        response_dict['hostname'] = url_parse.hostname  # 域名
        response_dict['path'] = url_parse.path  # 请求路径

        result = self.intercept(response_dict)
        if result['flag']:  # http请求命令拦截规则
            if result['rule_data'][8] == 1:  # 修改响应值
                response_dict['data'] = flow.response.get_text()
                data = self.falsify_response(result['rule_data'][5], response_dict)
                flow.response.text = data
                logger.info(f"{response_dict['url']} 响应值已篡改完成")

    def intercept(self, request_dict):
        """
        拦截
        :param request_dict:
        :return:
        """
        flag = 0    # Whether match mitm rule
        index = 0
        try:
            for i in range(len(self._data)):
                rule = self._data[i]
                index = i
                if rule[2] and rule[3]:
                    if self.recompile(rule[2], request_dict["hostname"], is_re=rule[7]):
                        flag = 1
                        break
                    elif self.recompile(rule[3], request_dict["path"], is_re=rule[7]):
                        flag = 1
                        break
                    else:
                        continue
                elif rule[2] and not rule[3]:
                    if self.recompile(rule[2], request_dict["hostname"], is_re=rule[7]):
                        flag = 1
                        break
                elif rule[3] and not rule[2]:
                    if self.recompile(rule[3], request_dict["path"], is_re=rule[7]):
                        flag = 1
                        break
                else:
                    continue
        except Exception:
            logger.error(traceback.format_exc())

        return {"flag": flag, "rule_data": self._data[index] if flag else None}

    def return_response(self, rule_data, request_dict):
        status_code = rule_data[4]
        if not status_code:
            status_code = 200

        try:
            if rule_data[6] == 1:
                with open(rule_data[5], 'r', encoding='utf-8') as f:
                    content = f.read()
            else:
                content = rule_data[5]
            try:
                content = json.dumps(self.replace_param(json.loads(content), request_dict))
            except Exception as err:
                logger.error(err)
                # logger.error(traceback.format_exc())

        except Exception as err:
            logger.error(traceback.format_exc())
            status_code = 500
            content = str(err)

        return {'status_code': status_code, 'content': content}

    def falsify_request(self, fields, request_dict):
        """
        篡改请求参数
        :param fields: 设置的修改字段
        :param request_dict: 提取出来的请求信息
        :return:
        """
        try:
            fields = json.loads(fields)
            url_dict = fields.get('requestUrl')
            body_dict = fields.get('requestBody')
            if url_dict:
                for k, v in url_dict.items():
                    url = self.tamper_url(k, urllib.parse.quote(v), request_dict['url'])
                    request_dict['url'] = url

            if body_dict:
                for k, v in body_dict.items():
                    data = self.tamper_body(k, v, request_dict['origin_data'])
                    request_dict['origin_data'] = data
        except:
            logger.error(traceback.format_exc())

        return request_dict['url'], request_dict['origin_data']

    def tamper_url(self, key, value, url):
        pattern = f'{key}=(.*?)&|{key}=(.*?)+'
        url = re.sub(pattern, f'{key}={value}&', url)
        return url

    def tamper_body(self, key, value, data, is_request = True):
        try:
            data_dic = json.loads(data)
            keys = [self.str_2_num(k) for k in key.split('.')]
            self.get_dict(keys, value, data_dic)
            return json.dumps(data_dic)
        except Exception as err:
            if is_request:
                logger.warning(f"POST请求体中的参数为：{data}")
                return self.tamper_url(key, value, data)
            else:
                logger.warning(f"响应值不是Json格式，{data}")
                return data

    def falsify_response(self, fields, response_dict):
        """
        篡改响应值
        :param fields: 设置的修改字段
        :param response_dict: 响应值
        :return:
        """
        try:
            fields = json.loads(fields)
            res_dict = fields.get('responseBody')
            if res_dict:
                for k, v in res_dict.items():
                    data = self.tamper_body(k, v, response_dict['data'], is_request=False)
                    response_dict['data'] = data
        except:
            logger.error(traceback.format_exc())
        return response_dict['data']

    def get_dict(self, keys, value, data):
        if len(keys) == 1:
            data[keys[0]] = value
        else:
            k = keys.pop(0)
            try:
                return self.get_dict(keys, value, data[k])
            except:
                logger.error(traceback.format_exc())
                data[k] = value

    @staticmethod
    def str_2_num(value: str):
        try:
            return int(value)
        except Exception as err:
            return value

    @staticmethod
    def replace_param(content, request_dict):
        """
        修改mock的返回值，定制化方法，可以根据自己的需求实现
        - 当响应值中的某个字段的值是变化的，需要和请求参数的值保持一致，则需要在这里处理；
        - 当响应值中的ID或其他字段的值需要动态变化，每次响应都要是不一样的值，则需要在这里加处理逻辑；
        :param content: 读取设置的返回值内容，是 dict or list
        :param request_dict: 请求相关数据，request_dict['hostname'] 是域名
                request_dict['path'] 是请求路径
                request_dict['query'] 是URL中的请求参数，GET和POST请求都可能会带
                request_dict['data'] 是POST请求的参数
        :return: 修改后的返回值
        """
        try:
            if request_dict['path'] == '':
                # 在这里写 根据接口添加处理逻辑
                pass
        except:
            logger.error(traceback.format_exc())

        return content

    @staticmethod
    def decode_query(query: str):
        data = {}
        if not query:
            return data
        params = query.split('&')
        for param in params:
            k, v = param.split('=')
            data.update({k: v})

        return data

    def decode_data(self, data: str):
        try:
            return json.loads(data)
        except Exception as err:
            logger.error(f'{err} -- {data}')
            # logger.error(traceback.format_exc())
            return self.decode_query(data)

    @staticmethod
    def recompile(pattern, string, is_re = 1):
        if is_re:
            res = re.search(pattern, string)
            if res:
                return True
            else:
                return False
        else:
            return pattern == string


async def app_server(q):
    s = SERVER(q)
    app = web.Application()
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('templates'))  # Add template to search path
    app.router.add_static(f'{getConfig("context")}/static',
                          path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'),
                          append_version=True)  # Add static files to the search path

    app.router.add_route('GET', f'{getConfig("context")}', s.home)
    app.router.add_route('GET', f'{getConfig("context")}/course', s.course)
    app.router.add_route('POST', f'{getConfig("context")}/isRun', s.isRun)
    app.router.add_route('GET', f'{getConfig("context")}/delete/{{Id}}', s.delete)
    app.router.add_route('GET', f'{getConfig("context")}/edit/{{Id}}', s.edit)
    app.router.add_route('POST', f'{getConfig("context")}/update', s.update)
    app.router.add_route('GET', f'{getConfig("context")}/reload', s.reload)
    app.router.add_route('POST', f'{getConfig("context")}/save', s.save)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, getConfig('host'), getConfig('port'))
    await site.start()


def main_server(q):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(app_server(q))
    loop.run_forever()


async def main():
    process_1 = Process(target=main_server, args=(q,))
    process_1.daemon = True
    process_1.start()

    options = Options(listen_host=getConfig('proxy_host'), listen_port=int(getConfig('proxy_port')), http2=True)
    proxy = DumpMaster(options, with_termlog=False, with_dumper=False)
    r_e = RequestEvent(q)
    proxy.addons.add(r_e)
    try:
        await proxy.run()
    except KeyboardInterrupt:
        proxy.shutdown()


if __name__ == '__main__':
    asyncio.run(main())
