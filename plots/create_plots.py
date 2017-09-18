#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
 * Copyright (c) 2017, Matthias Julius Kannwischer
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''


import csv
import math
import numpy as np
from os import listdir
from os.path import isfile, join
import matplotlib.pyplot as plt

def parse_csv(file):
    ifile = open(file, "rb")
    reader = csv.reader(ifile, delimiter=';')
    values = []
    for row in reader:
        values.append(int(row[6]))
    ifile.close()
    return values


def parse_all(path):
    values = [];
    for f in listdir(path):
        file = join(path, f)
        if isfile(file) and file.endswith(".log"):
            values.extend(parse_csv(file))
    return values


def hist_txt(x):
    return "mean= %0.3f\nmax= %d\nmin= %d\nmedian= %d" % (np.mean(x), max(x), min(x), np.median(x))

def plot_hist(x, fname):
    f = plt.figure(figsize=(11,5))
    plt.hist(x, range(min(x), max(x)+1), normed=True)
    plt.ylabel("relative frequency")
    plt.xlabel("number of required faulty signatures")
    #plt.figtext(.7, .7, hist_txt(x))



    table_data = [["mean", "%.1f" %np.mean(x)],["max", max(x)],["min", min(x)],["median","%d"%np.median(x)]]
    table = plt.table(cellText=table_data, colWidths = [0.05,0.05],
          loc='center right')

    table.scale(1.8,1.8)
    plt.tight_layout()
    f.savefig(fname)

def scatter_txt(x,y):
    txt = ""
    for p, d in zip(x, y):
        txt += "\np=%02d mean=%.3f" % (p, d)
    return txt

def plot_scatter(x, y, fname):
    f = plt.figure(figsize=(11,5))
    plt.plot(x,y, "x", ms=18.0)
    plt.ylabel("number of required faulty signatures")
    plt.xlabel("number of forgery trials p")
    plt.ylim(ymin=0)
    plt.ylim(ymax=math.ceil(max(y)+2))
    plt.tight_layout()
    plt.figtext(.1, .2, scatter_txt(x, y))
    #plt.show()
    f.savefig(fname)

def plot_boxplot(x, y, fname):
    f = plt.figure(figsize=(11,5))
    plt.ylabel("number of required faulty signatures")
    plt.xlabel("number of forgery trials p")
    plt.boxplot(y, labels=x, positions=x,showfliers=False)
    #plt.figtext(.8, .65,scatter_txt(x,[np.mean(a) for a in y]));
    table_data = zip(x,map(lambda y: "%.1f"%np.mean(y), y))
    table_cols = ["p", "mean"]
    table = plt.table(cellText=table_data,
                  colLabels=table_cols, loc='center right',bbox=[0.78, 0.55, 0.20, 0.4])

    plt.tight_layout()
    f.savefig(fname)

plt.style.use('classic')

data_P_1_N_32 = parse_all("../data/P_1/N_32")
plot_hist(data_P_1_N_32,"FA_P_1_N_32.pdf")

data_P_1_N_64 = parse_all("../data/P_1/N_64")
plot_hist(data_P_1_N_64,"FA_P_1_N_64.pdf")


data_P_1 = data_P_1_N_32[:1000]
data_P_2 = parse_all("../data/P_NOT1/P_2")[:1000]
data_P_4 = parse_all("../data/P_NOT1/P_4")[:1000]
data_P_8 = parse_all("../data/P_NOT1/P_8")[:1000]
data_P_16 = parse_all("../data/P_NOT1/P_16")[:1000]
data_P_24 = parse_all("../data/P_NOT1/P_24")[:1000]
data_P_32 = parse_all("../data/P_NOT1/P_32")[:1000]

p = [1,2,4,8,16,24,32]
d = [np.mean(data_P_1), np.mean(data_P_2), np.mean(data_P_4), np.mean(data_P_8), np.mean(data_P_16), np.mean(data_P_24), np.mean(data_P_32)]
plot_scatter(p,d, "FA_P_1_2_4_8_16_32.pdf")

d = [data_P_1, data_P_2, data_P_4, data_P_8, data_P_16, data_P_24, data_P_32]
plot_boxplot(p, d, "FA_P_boxplot.pdf")
