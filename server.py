#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari

import os
import time
import json
import asyncio
import traceback
import jinja2
import aiohttp_jinja2
from aiohttp import web
from config import getConfig
from logger import logger
import sqlExecuter


class SERVER(object):
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
            # self.q.put(sqlExecuter.reload())
            return web.json_response({'code': 1, 'msg': 'successful', 'data': None})
        except Exception as err:
            return web.json_response({'code': 0, 'msg': str(err), 'data': None})


async def app_server():
    s = SERVER()
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
    # app.router.add_route('GET', f'{getConfig("context")}/reload', s.reload)
    app.router.add_route('POST', f'{getConfig("context")}/save', s.save)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, getConfig('host'), getConfig('port'))
    await site.start()


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(app_server())
    loop.run_forever()


if __name__ == '__main__':
    main()
