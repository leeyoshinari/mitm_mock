#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari

import os
import re
import time
import asyncio
import threading
import urllib.parse
import mitmproxy.http
from multiprocessing import Process, Queue
from mitmproxy.options import Options
from mitmproxy.proxy.config import ProxyConfig
from mitmproxy.proxy.server import ProxyServer
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import ctx, http
import jinja2
import aiohttp_jinja2
from aiohttp import web
from config import getConfig
import sqlExecuter


q = Queue()


class SERVER(object):
    def __init__(self, q):
        self.q = q

    @staticmethod
    async def home(request):
        return aiohttp_jinja2.render_template('home.html', request, context={'datas': sqlExecuter.home(request)})

    @staticmethod
    async def isRun(request):
        try:
            data = await request.post()
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
            data = await request.post()
            sqlExecuter.update(data)
            return web.json_response({'code': 1, 'msg': 'successful', 'data': None})
        except Exception as err:
            return web.json_response({'code': 0, 'msg': str(err), 'data': None})

    @staticmethod
    async def save(request):
        try:
            data = await request.post()
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
            time.sleep(0.5)

    def http_connect(self, flow: mitmproxy.http.HTTPFlow):
        """
        An HTTP CONNECT request was received. Setting a non 2xx response on the flow will return the response
        to the client abort the connection. CONNECT requests and responses do not generate the usual
        HTTP handler events. CONNECT requests are only valid in regular and upstream proxy modes.
        """
        pass

    def request(self, flow: mitmproxy.http.HTTPFlow):
        # request_scheme = flow.request.scheme  # 请求协议
        request_method = flow.request.method  # 请求方式
        domain_name = flow.request.headers.get("Host")  # 域名
        if request_method == 'GET':
            url = flow.request.url      # url
            url_parse = urllib.parse.urlparse(url)      # 解析url
            url_path = url_parse.path  # 请求路径
            # url_params = url_parse.query  # 请求参数，url传参
        else:
            url_path = flow.request.path
            # url_params = flow.request.get_text()

        data = self.intercept(domain_name, url_path)
        if data:
            flow.response = http.HTTPResponse.make(status_code=data['status_code'], content=data['content'])
        else:
            pass

    def response(self, flow: mitmproxy.http.HTTPFlow):
        pass

    def intercept(self, domain_name, url_path):
        """
        拦截
        :param domain_name:
        :param url_path:
        :return:
        """
        flag = 0
        index = 0
        for i in range(len(self._data)):
            rule = self._data[i]
            index = i
            if rule[2] and rule[3]:
                if self.recompile(rule[2], domain_name):
                    flag = 1
                    break
                elif self.recompile(rule[3], url_path):
                    flag = 1
                    break
                else:
                    continue
            elif rule[2] and not rule[3]:
                if self.recompile(rule[2], domain_name):
                    flag = 1
                    break
            elif rule[3] and not rule[2]:
                if self.recompile(rule[3], url_path):
                    flag = 1
                    break
            else:
                continue

        if flag:
            return self.return_response(self._data[index][4], self._data[index][5], self._data[index][6])
        else:
            return {}

    @staticmethod
    def return_response(status_code, response, is_file):
        if not status_code:
            status_code = 200

        try:
            if is_file == 1:
                with open(response, 'r', encoding='utf-8') as f:
                    content = f.read()
            else:
                content = response
        except Exception as err:
            status_code = 500
            content = str(err)

        return {'status_code': status_code, 'content': content}


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
    app.router.add_static('/static',
                          path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'),
                          append_version=True)  # Add static files to the search path

    app.router.add_route('GET', '', s.home)
    app.router.add_route('POST', '/isRun', s.isRun)
    app.router.add_route('GET', '/delete/{Id}', s.delete)
    app.router.add_route('GET', '/edit/{Id}', s.edit)
    app.router.add_route('POST', '/update', s.update)
    app.router.add_route('GET', '/reload', s.reload)
    app.router.add_route('POST', '/save', s.save)

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
    config = ProxyConfig(options)
    proxy = ProxyMaster(options, with_termlog=False, with_dumper=False)
    proxy.server = ProxyServer(config)
    r_e = RequestEvent(q)
    proxy.addons.add(r_e)
    proxy.start_run()


if __name__ == '__main__':
    main()
