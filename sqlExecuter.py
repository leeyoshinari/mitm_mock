#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari

import time
from sqlite import Sqlite
from config import getConfig
from logger import logger


table_name = getConfig('table_name')
INSERT_SQL = "INSERT INTO {} {} VALUES {};"
SELECT_SQL = "SELECT * FROM {} ORDER BY UPDATE_TIME DESC;"
UPDATE_SQL = "UPDATE {} SET {} WHERE id = {};"
DELETE_SQL = "DELETE FROM {} WHERE id = {};"
EDIT_SQL = "SELECT * FROM {} WHERE id = {};"
FIELD = ("id", "name", "domain_name", "url_path", "status_code", "response", "is_file", "is_regular", "is_valid", "update_time")

def home(request):
    sql_con = Sqlite()
    sql_con.cur.execute(SELECT_SQL.format(table_name))
    data = sql_con.cur.fetchall()
    del sql_con
    return data


def isRun(data):
    sql_con = Sqlite()
    ID = data.get('Id')
    is_run = data.get('isRun')
    sql_con.cur.execute(UPDATE_SQL.format(table_name, f'is_valid = {is_run}, update_time = {int(time.time())}', ID))
    sql_con.con.commit()
    logger.info(f'{ID} 设置为 {is_run}')
    del sql_con


def delete(ID):
    sql_con = Sqlite()
    sql_con.cur.execute(DELETE_SQL.format(table_name, ID))
    sql_con.con.commit()
    logger.info(f'{ID} 删除成功')
    del sql_con


def edit(ID):
    sql_con = Sqlite()
    sql_con.cur.execute(EDIT_SQL.format(table_name, ID))
    data = sql_con.cur.fetchall()
    return data[0]


def save(data):
    sql_con = Sqlite()
    name = data.get('name')
    domain_name = data.get('domain_name')
    url_path = data.get('url_path')
    status_code = data.get('status_code')
    response = data.get('response')
    is_file = data.get('is_file')
    is_re = data.get('is_re')
    is_valid = 1

    if is_file:
        is_file = int(is_file)
        if is_file < 0 or is_file > 1:
            raise Exception("响应值是否是文件 的值必须是 0 或 1")
    else:
        is_file = 0

    if is_re:
        is_re = int(is_re)
        if is_re < 0 or is_re > 1:
            raise Exception("是否正则匹配规则 的值必须是 0 或 1")
    else:
        is_re = 1

    insert_date = (int(time.time()*1000), name, domain_name, url_path, status_code, response,
                   is_file, is_re, is_valid, int(time.time()))
    sql_con.cur.execute(INSERT_SQL.format(table_name, FIELD, insert_date))
    sql_con.con.commit()
    logger.info(f'{name}保存成功')
    del sql_con


def update(data):
    sql_con = Sqlite()
    ID = data.get('ID')
    name = data.get('name')
    domain_name = data.get('domain_name')
    url_path = data.get('url_path')
    status_code = data.get('status_code')
    response = data.get('response')
    is_file = data.get('is_file')
    is_re = data.get('is_re')

    if is_file:
        is_file = int(is_file)
        if is_file < 0 or is_file > 1:
            raise Exception("响应值是否是文件 的值必须是 0 或 1")
    else:
        is_file = 0

    if is_re:
        is_re = int(is_re)
        if is_re < 0 or is_re > 1:
            raise Exception("是否正则匹配规则 的值必须是 0 或 1")
    else:
        is_re = 1

    update_date = f"name = '{name}', domain_name = '{domain_name}', url_path = '{url_path}', status_code = {status_code}, " \
                  f"response = '{response}', is_file = {is_file}, is_regular = {is_re}, update_time = {int(time.time())}"

    sql_con.cur.execute(UPDATE_SQL.format(table_name, update_date, ID))
    sql_con.con.commit()
    logger.info(f'{ID}更新成功')
    del sql_con


def reload(request):
    sql_con = Sqlite()
    sql_con.cur.execute("SELECT * FROM {} WHERE is_valid = 1 ORDER BY UPDATE_TIME DESC;".format(table_name))
    data = sql_con.cur.fetchall()
    del sql_con
    return data
