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
            sqlExecuter.update(data)
            return web.json_response({'code': 1, 'msg': 'successful', 'data': None})
        except Exception as err:
            return web.json_response({'code': 0, 'msg': str(err), 'data': None})

    @staticmethod
    async def save(request):
        try:
            data = json.loads(await request.text())
            sqlExecuter.save(data)
            return web.json_response({'code': 1, 'msg': 'successful', 'data': None})
        except Exception as err:
            return web.json_response({'code': 0, 'msg': str(err), 'data': None})

    async def reload(self, request):
        try:
            self.q.put(sqlExecuter.reload(request))
            return web.json_response({'code': 1, 'msg': 'successful', 'data': None})
        except Exception as err:
            return web.json_response({'code': 0, 'msg': str(err), 'data': None})


class RequestEvent(object):
    def __init__(self, q):
        self._data = []
        self.q = q

        thread_01 = threading.Thread(target=self.get_queue)
        thread_01.setDaemon(True)
        thread_01.start()

    def get_queue(self):
        while True:
            self._data = self.q.get()
            time.sleep(1)

    def http_connect(self, flow: mitmproxy.http.HTTPFlow):
        """
        An HTTP CONNECT request was received. Setting a non 2xx response on the flow will return the response
        to the client abort the connection. CONNECT requests and responses do not generate the usual
        HTTP handler events. CONNECT requests are only valid in regular and upstream proxy modes.
        """
        pass

    def request(self, flow: mitmproxy.http.HTTPFlow):
        request_dict = {'method': '', 'scheme': '', 'hostname': '', 'port': 80, 'path': '',
                        'query': '', 'data': '', 'fragment': ''}
        request_dict['method'] = flow.request.method  # 请求方式
        url_parse = urllib.parse.urlparse(flow.request.url)      # 解析url
        request_dict['scheme'] = url_parse.scheme   # 协议
        request_dict['hostname'] = url_parse.hostname   # 域名
        request_dict['port'] = flow.request.port    # 端口
        request_dict['path'] = url_parse.path  # 请求路径
        request_dict['query'] = self.decode_query(urllib.parse.unquote(url_parse.query))  # URL中的请求参数
        request_dict['fragment'] = url_parse.fragment
        data = flow.request.get_text()
        request_dict['data'] = self.decode_data(data) if data else data # post请求的参数

        logger.info(f'{request_dict["scheme"]} - {request_dict["method"]} - {request_dict["hostname"]}:'
                    f'{request_dict["port"]} - {request_dict["path"]}')
        data = self.intercept(request_dict)
        if data:
            flow.response = http.Response.make(status_code=data['status_code'], content=data['content'])
        else:
            pass

    def response(self, flow: mitmproxy.http.HTTPFlow):
        pass

    def intercept(self, request_dict):
        """
        拦截
        :param domain_name:
        :param url_path:
        :return:
        """
        flag = 0    # Whether match mitm rule
        index = 0
        try:
            for i in range(len(self._data)):
                rule = self._data[i]
                index = i
                if rule[2] and rule[3]:
                    if self.recompile(rule[2], request_dict["hostname"]):
                        flag = 1
                        break
                    elif self.recompile(rule[3], request_dict["path"]):
                        flag = 1
                        break
                    else:
                        continue
                elif rule[2] and not rule[3]:
                    if self.recompile(rule[2], request_dict["hostname"]):
                        flag = 1
                        break
                elif rule[3] and not rule[2]:
                    if self.recompile(rule[3], request_dict["path"]):
                        flag = 1
                        break
                else:
                    continue
        except Exception:
            logger.error(traceback.format_exc())

        if flag:
            return self.return_response(self._data[index], request_dict)
        else:
            return {}

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
            except:
                logger.error(content)
                logger.error(traceback.format_exc())

        except Exception as err:
            logger.error(traceback.format_exc())
            status_code = 500
            content = str(err)

        return {'status_code': status_code, 'content': content}

    @staticmethod
    def replace_param(content, request_dict):
        """
        修改mock的返回值
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

    @staticmethod
    def decode_data(data: str):
        try:
            return json.loads(data)
        except:
            # logger.error(data)
            # logger.error(traceback.format_exc())
            return data

    @staticmethod
    def recompile(pattern, string):
        res = re.search(pattern, string)
        if res:
            return True
        else:
            return False


class ProxyMaster(DumpMaster):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def start_run(self):
        try:
            DumpMaster.run(self)
        except KeyboardInterrupt:
            self.shutdown()


async def app_server(q):
    s = SERVER(q)
    app = web.Application()
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('templates'))  # Add template to search path
    app.router.add_static(f'{getConfig("context")}/static',
                          path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'),
                          append_version=True)  # Add static files to the search path

    app.router.add_route('GET', f'{getConfig("context")}', s.home)
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


def main():
    process_1 = Process(target=main_server, args=(q,))
    process_1.daemon = True
    process_1.start()

    options = Options(listen_host=getConfig('proxy_host'), listen_port=int(getConfig('proxy_port')), http2=True)
    proxy = ProxyMaster(options, with_termlog=False, with_dumper=False)
    r_e = RequestEvent(q)
    proxy.addons.add(r_e)
    proxy.start_run()


if __name__ == '__main__':
    main()
