#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari

import sqlite3
from config import getConfig


class Sqlite(object):
    def __init__(self):
        self.sqlite_path = getConfig('sqlite_path')
        self.table_name = getConfig('table_name')
        self.con = None
        self.cur = None

        self.connect()
        self.initialize()

    def connect(self):
        self.con = sqlite3.connect(self.sqlite_path)
        self.cur = self.con.cursor()

    def initialize(self):
        sql = "CREATE TABLE IF NOT EXISTS {} (" \
              "id VARCHAR(20) PRIMARY KEY NOT NULL," \
              "name VARCHAR(50)," \
              "domain_name VARCHAR(50)," \
              "url_path VARCHAR(200)," \
              "status_code INTEGER," \
              "response TEXT," \
              "is_file INTEGER," \
              "is_valid INTEGER," \
              "update_time INTEGER);".format(self.table_name)
        self.cur.execute(sql)
        self.con.commit()

    def __del__(self):
        self.con.close()


if __name__ == '__main__':
    Sqlite()
