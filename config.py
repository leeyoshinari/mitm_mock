#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari

import configparser


cfg = configparser.ConfigParser()
cfg.read('config.ini', encoding='utf-8')


def getConfig(key):
    if key == 'backupCount':
        return cfg.getint('config', key, fallback=7)
    else:
        return cfg.get('config', key, fallback=None)
