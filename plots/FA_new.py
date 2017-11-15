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
from itertools import product

def parse_csv_exp1(i):
    ifile = open("../data_new/P_1/N_32/%d.log"%i, "rb")
    reader = csv.reader(ifile, delimiter=';')
    values = []
    for row in reader:
        values.append(int(row[10]))
    ifile.close()
    return values

def parse_csv_exp2(k, p):
    ifile = open("../data_new/P_N1/N_32/k_%d_p_%d.log"%(k,p), "rb")
    reader = csv.reader(ifile, delimiter=';')
    values = []
    for row in reader:
        values.append(int(row[10]))
    ifile.close()
    return values


def plot_lines(x, exp, theo, fname):
    f = plt.figure(figsize=(11,5))
    
    plt.ylim(ymin=-0.1)
    plt.ylim(ymax=1.1)
    plt.plot(x,theo,color="orange")
    plt.plot(x,exp,color="blue")
    plt.xlabel("number of faulty signatures")
    plt.ylabel("success probability")
    plt.tight_layout()
    #plt.figtext(.1, .2, scatter_txt(x, y))
    #plt.show()
    f.savefig(fname)

def prob(W, ell,q):
    W = float(W)
    ell = float(ell)
    q = float(q+1)
    s = 0
    for x in range(0,int(W)):
       s += 1 - ((W-(x+1))/W)**(q+1)
    s = s**ell
    return s/(W**ell)



#print parse_csv()


# 1 means failure; 0 is success
data = map(lambda(l): (sum(l), len(l)), map(lambda (i): parse_csv_exp1(i), xrange(1,111)))
exp_results = map(lambda (fail, all): (float(all)-fail)/all, data)
theoretical_results = map(lambda(q): prob(16, 67, q), xrange(1,111))

plot_lines(range(1,111), exp_results, theoretical_results, "FA_new_N32.pdf")


ks = [5, 10, 15, 20, 30, 40, 50]
ps = [1, 2, 4, 8, 16, 32, 64]
tuples = map(lambda(k, p): (k,p),  product(ks,ps))
data   = map(lambda(k,p): (k, p, parse_csv_exp2(k,p)), tuples)
exp_results = map(lambda(k,p, fail, all): (k,p, (float(all)-fail)/all), map(lambda (k,p,l): (k,p,sum(l), len(l)), data))

lines = map(lambda(k): filter(lambda(ki, p, prob): ki == k , exp_results), ks)

def plot_lines_2(lines, fname):
    f = plt.figure(figsize=(11,5))
    plt.ylim(ymin=-0.1)
    plt.ylim(ymax=1.1)
    for line in lines:
        x = map(lambda(k,p,prob): p, line)
        y = map(lambda(k,p,prob): prob, line)
        plt.plot(x,y, ".", ms=9.0,color="grey")
        plt.plot(x,y,label="k=%d"%line[0][0])
        
        
    legend = plt.legend(loc='lower right', shadow=True, fontsize='x-large')
    plt.ylabel("success probability")
    plt.xlabel("number of forgery attempts p")
    plt.tight_layout()
    f.savefig(fname)

plot_lines_2(lines, "FA_new_PN1.pdf")