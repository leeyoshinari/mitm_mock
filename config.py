#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari

import configparser


cfg = configparser.ConfigParser()
cfg.read('config.ini', encoding='utf-8')


def getConfig(key):
    return cfg.get('config', key, fallback=None)
